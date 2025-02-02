use std::{
    cell::{Ref, RefCell, RefMut},
    collections::HashSet,
    io::Error,
    pin::Pin,
    rc::Rc,
    sync::{Arc, LazyLock, Mutex},
};

use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    ChaCha20,
};
use obliviate_core::{
    crypter::{aes::Aes256Ctr, ivs::SequentialIvg},
    hasher::sha3::{Sha3_256, SHA3_256_MD_SIZE},
    kms::{
        khf::Khf, KeyManagementScheme, PersistableKeyManagementScheme, StableKeyManagementScheme,
    },
    wal::SecureWAL,
};
use rand::rngs::OsRng;

pub type MyKhf = Khf<OsRng, SequentialIvg, Aes256Ctr, Sha3_256, SHA3_256_MD_SIZE>;
struct ObjectStore<D: Disk> {
    fs: Pin<Box<FileSystem<D>>>,
    kms: Mutex<Kms<D>>,
}

struct Kms<D: Disk> {
    wal: Rc<
        RefCell<
            SecureWAL<
                D,
                <MyKhf as KeyManagementScheme>::LogEntry,
                SequentialIvg,
                Aes256Ctr,
                SHA3_256_MD_SIZE,
            >,
        >,
    >,
    khf: Rc<RefCell<MyKhf>>,
}

impl<D> Kms<D>
where
    D: Disk,
    std::io::Error: From<fatfs::Error<D::Error>>,
{
    fn open_khf(
        fs: Arc<Mutex<fatfs::FileSystem<D, NullTimeProvider, LossyOemCpConverter>>>,
        root_key: [u8; 32],
    ) -> MyKhf {
        let khf = MyKhf::load(root_key, "lethe/khf", &fs.lock().unwrap())
            .unwrap_or_else(|_e| MyKhf::new());
        khf
    }

    fn open_wal(
        fs: Arc<Mutex<fatfs::FileSystem<D, NullTimeProvider, LossyOemCpConverter>>>,
        root_key: [u8; 32],
    ) -> SecureWAL<
        D,
        <MyKhf as KeyManagementScheme>::LogEntry,
        SequentialIvg,
        Aes256Ctr,
        SHA3_256_MD_SIZE,
    > {
        fs.lock().unwrap().root_dir().create_dir("lethe").unwrap();
        SecureWAL::open("lethe/wal".to_string(), root_key, fs.clone()).unwrap()
    }
    pub fn open(
        fs: Arc<Mutex<fatfs::FileSystem<D, NullTimeProvider, LossyOemCpConverter>>>,
        root_key: [u8; 32],
    ) -> Self {
        Self {
            khf: Rc::new(RefCell::new(Self::open_khf(fs.clone(), root_key))),
            wal: Rc::new(RefCell::new(Self::open_wal(fs, root_key))),
        }
    }

    pub fn khf(&self) -> Ref<MyKhf> {
        self.khf.borrow()
    }

    pub fn khf_mut(&self) -> RefMut<MyKhf> {
        self.khf.borrow_mut()
    }

    pub fn wal(
        &self,
    ) -> Ref<
        SecureWAL<
            D,
            <MyKhf as KeyManagementScheme>::LogEntry,
            SequentialIvg,
            Aes256Ctr,
            SHA3_256_MD_SIZE,
        >,
    > {
        self.wal.borrow()
    }

    pub fn wal_mut(
        &mut self,
    ) -> RefMut<
        SecureWAL<
            D,
            <MyKhf as KeyManagementScheme>::LogEntry,
            SequentialIvg,
            Aes256Ctr,
            SHA3_256_MD_SIZE,
        >,
    > {
        self.wal.borrow_mut()
    }
}

fn get_dir_path<'a, D>(
    fs: &'a mut fatfs::FileSystem<D, DefaultTimeProvider, LossyOemCpConverter>,
    encoded_obj_id: &EncodedObjectId,
) -> Result<Dir<'a, D, DefaultTimeProvider, LossyOemCpConverter>, Error>
where
    D: Disk,
    std::io::Error: From<fatfs::Error<D::Error>>,
{
    let subdir = fs
        .root_dir()
        .create_dir("ids")?
        .create_dir(&encoded_obj_id[0..1])?;
    Ok(subdir)
}

// while 'a represents the lifetime of the Disk
impl<D> ObjectStore<D>
where
    D: Disk,
    std::io::Error: From<fatfs::Error<D::Error>>,
    fatfs::Error<std::io::Error>: From<<D as IoBase>::Error>,
    fatfs::Error<<D as IoBase>::Error>: From<std::io::Error>,
    std::io::Error: From<D::Error>,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    /// Overwrites the existing disk with a new format.
    /// # Safety
    /// Might not securely delete what used to be on the disk.
    ///
    /// # Panics
    /// When there is a Disk error or when a lock is not
    /// able to be claimed
    pub fn reformat(&mut self, mut disk: D, root_key: [u8; 32]) {
        let _unused = LOCK.lock();
        FileSystem::format(&mut disk);
        self.fs = Box::pin(FileSystem::open_fs(disk));
        self.kms = Mutex::new(Kms::open(self.fs.fs_as_owned(), root_key));
    }

    fn fs(&self) -> &Mutex<fatfs::FileSystem<D>> {
        self.fs.fs()
    }
    /// Will either open the disk if it is properly formatted
    /// or will reformat the disk.
    /// # Safety
    /// If the disk gets corrupted then it might not securely delete
    /// what used to be on the disk.
    pub fn open(disk: D, root_key: [u8; 32]) -> Self {
        let fs = FileSystem::open_fs(disk);
        let fs_ref = fs.fs_as_owned();
        Self {
            fs: Box::pin(fs),
            kms: Mutex::new(Kms::open(fs_ref, root_key)),
        }
    }

    /// Returns the disk length of a given object on disk.
    pub fn disk_length(&self, obj_id: u128) -> Result<u64, Error> {
        let mut fs = self.fs().lock().unwrap();
        let id = encode_obj_id(obj_id);
        let dir = get_dir_path(&mut fs, &id)?;
        let mut file = dir.open_file(&id)?;
        let len = file.seek(SeekFrom::End(0))?;
        Ok(len)
    }
    /// Either gets a previously set config_id from disk or returns None
    pub fn get_config_id(&self) -> Result<Option<u128>, Error> {
        let fs = self.fs().lock().unwrap();
        let file = fs.root_dir().open_file("config_id");
        let mut file = match file {
            Ok(file) => file,
            Err(fatfs::Error::NotFound) => return Ok(None),
            err => err?,
        };
        let mut buf = [0u8; 16];
        file.read_exact(&mut buf)?;
        Ok(Some(u128::from_le_bytes(buf)))
    }
    /// Stores a config_id onto the disk.
    pub fn set_config_id(&self, id: u128) -> Result<(), Error> {
        let fs = self.fs().lock().unwrap();
        let mut file = fs.root_dir().create_file("config_id")?;
        file.truncate()?;
        let bytes = id.to_le_bytes();
        file.write_all(&bytes)?;
        Ok(())
    }

    /// Returns true if file was created and false if the file already existed.
    pub fn create_object(&self, obj_id: u128) -> Result<bool, Error> {
        let b64 = encode_obj_id(obj_id);
        let mut fs = self.fs().lock().unwrap();
        let subdir = get_dir_path(&mut fs, &b64)?;
        // try to open it to check if it exists.
        let res = subdir.open_file(&b64);
        match res {
            Ok(_) => Ok(false),
            Err(e) => match e {
                fatfs::Error::NotFound => {
                    // khf.derive_mut(&wal, hash_obj_id(obj_id))
                    //     .expect("shouldn't panic since khf implementation doesn't panic");
                    subdir.create_file(&b64)?;
                    Ok(true)
                }
                _ => Err(e.into()),
            },
        }
    }

    pub fn kms_lock(&self) -> std::sync::MutexGuard<'_, Kms<D>> {
        self.kms.lock().unwrap()
    }
    /// unlinks (aka deletes) the object at `obj_id`.
    /// # Safety
    /// To do secure deletion on deletes you must call an epoch
    /// before saving.
    pub fn unlink_object(&mut self, obj_id: u128) -> Result<(), Error> {
        let _unused = LOCK.lock().unwrap();
        let b64 = encode_obj_id(obj_id);
        // let (khf, wal) = (kms.khf_mut(), kms.wal_mut());
        // khf.delete(&wal, hash_obj_id(obj_id))
        //     .map_err(Error::other)?;
        let extents = {
            let mut fs = self.fs().lock().unwrap();
            let subdir = get_dir_path(&mut fs, &b64)?;
            let mut file = subdir.open_file(&b64)?;
            file.extents().collect::<Vec<_>>().into_iter()
        };
        for extent in extents {
            let id = extent?.offset / crate::fs::PAGE_SIZE as u64;
            let kms = self.kms_lock();

            kms.khf_mut().delete(&kms.wal(), id).map_err(Error::other)?;
        }
        let mut fs = self.fs().lock().unwrap();
        let subdir = get_dir_path(&mut fs, &b64)?;
        subdir.remove(&b64)?;
        Ok(())
    }

    pub fn get_all_object_ids(&self) -> Result<Vec<u128>, Error> {
        let fs = self.fs().lock().unwrap();
        let id_root = fs.root_dir().create_dir("ids")?;
        let mut out = Vec::new();
        for folder in id_root.iter() {
            let folder = folder?;
            for file in folder.to_dir().iter() {
                let file = file?;
                let name = file.file_name();
                if name.len() != 32 {
                    continue; // ., ..
                }
                let id = u128::from_str_radix(&name, 16);
                if let Ok(id) = id {
                    out.push(id);
                }
            }
        }
        Ok(out)
    }

    fn get_symmetric_cipher(&self, disk_offset: u64) -> Result<ChaCha20, Error> {
        // let (mut khf, wal) = get_khf_locks();
        let kms = self.kms_lock();
        let chunk_id = disk_offset / (PAGE_SIZE as u64);
        let key = kms
            .khf_mut()
            .derive_mut(&kms.wal(), chunk_id)
            .map_err(Error::other)?;
        get_symmetric_cipher_from_key(disk_offset, key)
    }

    fn get_symmetric_cipher_from_key(disk_offset: u64, key: [u8; 32]) -> Result<ChaCha20, Error> {
        let chunk_id = disk_offset / (PAGE_SIZE as u64);
        let offset = disk_offset % (PAGE_SIZE as u64);
        let bytes = chunk_id.to_le_bytes();
        let nonce: [u8; 12] = [
            0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
            bytes[7],
        ];

        let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
        cipher.seek(offset);
        Ok(cipher)
    }

    pub fn read_exact(&mut self, obj_id: u128, buf: &mut [u8], off: u64) -> Result<(), Error> {
        let _unused = LOCK.lock().unwrap();
        let b64 = encode_obj_id(obj_id);
        let mut fs = self.fs().lock().unwrap();
        let subdir = get_dir_path(&mut fs, &b64)?;
        let mut file = subdir.open_file(&b64)?;
        file.seek(fatfs::SeekFrom::Start(off))?;
        let mut rw_proxy = ReadWriteProxy::new(
            &mut file,
            |disk: &mut D,
             disk_offset: u64,
             buffer: &mut [u8]|
             -> Result<usize, fatfs::Error<D::Error>> {
                let out = disk.read(buffer)?;
                let mut cipher = self
                    .get_symmetric_cipher(disk_offset)
                    .map_err(|e| Error::other(e))?;
                cipher.apply_keystream(buffer);
                Ok(out)
            },
            || {},
        );
        fatfs::Read::read_exact(&mut rw_proxy, buf)?;
        Ok(())
    }

    pub fn write_all(&self, obj_id: u128, buf: &[u8], off: u64) -> Result<(), Error> {
        let _unused = LOCK.lock().unwrap();
        let b64 = encode_obj_id(obj_id);
        // call to get_khf_locks to make sure that khf is already initialized for
        // the later "get_symmetric_cipher" call
        let mut fs = self.fs().lock().unwrap();
        let subdir = get_dir_path(&mut fs, &b64)?;
        let mut file = subdir.open_file(&b64)?;
        let _new_pos = file.seek(fatfs::SeekFrom::Start(off))?;
        let extents_before: HashSet<WrappedExtent> = file
            .extents()
            .map(|v| v.map(WrappedExtent::from))
            .try_collect()?;
        let mut rw_proxy = ReadWriteProxy::new(
            &mut file,
            || {},
            |disk: &mut D, offset: u64, buffer: &[u8]| -> Result<usize, fatfs::Error<D::Error>> {
                let mut cipher = self.get_symmetric_cipher(offset)?;
                let mut encrypted = vec![0u8; buffer.len()];
                cipher
                    .apply_keystream_b2b(buffer, &mut encrypted)
                    .map_err(|e| Error::other(e))?;
                let out = disk.write(&encrypted)?;
                Ok(out)
            },
        );
        fatfs::Write::write_all(&mut rw_proxy, buf)?;
        let extents_after: HashSet<WrappedExtent> = file
            .extents()
            .map(|v| v.map(WrappedExtent::from))
            .try_collect()?;
        // Should never add extents to a file after writing to a file.
        assert!(extents_before.difference(&extents_after).next() == None);
        Ok(())
    }

    pub fn advance_epoch(&mut self, root_key: [u8; 32]) -> Result<(), Error> {
        let _unused = LOCK.lock().unwrap();
        let kms = self.kms_lock();
        let updated_keys = kms.khf_mut().update(&kms.wal()).map_err(Error::other)?;
        drop(kms);
        for (id, key) in updated_keys {
            let mut buf = vec![0; PAGE_SIZE];
            // let fs = self.fs().lock().unwrap();
            let mut disk = self.fs.disk().clone();
            let disk_offset = id * super::fs::PAGE_SIZE as u64;
            disk.seek(SeekFrom::Start(disk_offset))?;
            disk.read_exact(buf.as_mut_slice())?;
            let mut cipher =
                get_symmetric_cipher_from_key(disk_offset, key).map_err(|e| Error::other(e))?;
            cipher.apply_keystream(&mut buf);
            disk.seek(SeekFrom::Start(disk_offset))?;
            let mut cipher = self
                .get_symmetric_cipher(disk_offset)
                .map_err(|e| Error::other(e))?;
            cipher.apply_keystream(&mut buf);
            disk.write_all(&mut buf)?;
        }
        let kms = self.kms_lock();
        let mut khf = kms.khf_mut();
        {
            let fs = self.fs().lock().unwrap();
            {
                fs.root_dir().create_dir("tmp/")?
            };
            khf.persist(root_key, "tmp/khf", &fs)
                .map_err(Error::other)?;
            // Ideally would be atomic from here...
            let lethe = fs.root_dir().create_dir("lethe/")?;
            let res = lethe.rename("khf", &fs.root_dir(), "old/khf");
            match res {
                Err(fatfs::Error::NotFound) => {}
                r => r?,
            };
            // FIXME: Recover keys from old/khf if it crashes here
            fs.root_dir().rename("tmp/khf", &lethe, "khf")?;
            {
                let mut old_file = fs.root_dir().open_file("old/khf")?;
                // override old file with zeroes
                while old_file.write(&[0u8; 4096])? != 0 {}
            }
            let mut file = fs.root_dir().open_file("lethe/khf")?;
            let len_serialized = file.seek(fatfs::SeekFrom::End(0)).unwrap();
            assert!(len_serialized != 0);
            drop(file);
            // needs to drop lethe to let fs be dropped.
            drop(lethe);
        } // ...to here.
        let mut kms = self.kms_lock();
        kms.wal_mut().clear().map_err(Error::other)?;
        Ok(())
    }
}

// // FIXME should use a randomly generated root key for each device.
// pub const ROOT_KEY: [u8; 32] = [0; 32];

fn get_symmetric_cipher_from_key(disk_offset: u64, key: [u8; 32]) -> Result<ChaCha20, Error> {
    let chunk_id = disk_offset / (PAGE_SIZE as u64);
    let offset = disk_offset % (PAGE_SIZE as u64);
    let bytes = chunk_id.to_le_bytes();
    let nonce: [u8; 12] = [
        0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ];

    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.seek(offset);
    Ok(cipher)
}

/// To avoid dealing with race conditions I lock every external function call
/// at the entrance of the function.
static LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

use fatfs::{
    DefaultTimeProvider, Dir, IoBase, LossyOemCpConverter, NullTimeProvider, Read as _,
    ReadWriteProxy, Seek, SeekFrom, Write as _,
};

use crate::{
    fs::{Disk, FileSystem, PAGE_SIZE},
    wrapped_extent::WrappedExtent,
};

type EncodedObjectId = String;

fn encode_obj_id(obj_id: u128) -> EncodedObjectId {
    format!("{:0>32x}", obj_id)
}
