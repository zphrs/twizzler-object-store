# Sparse File Format

Directory format within fat32. Values within `{}` are wildcards.

```
└── ids
    └── {first_obj_id_char:0-f}
        └── {first_obj_id_char+rest_of_obj_id}
            ├── .metadata
            └── chunks
                └── {chunk_id}
```

All objects are assumed to be sparse. 

If a write partially spans an existing range and partially spans empty space *after* that existing range then the {chunk_id} file will get appended to. If a write partially spans an existing range and partially spans empty space *before* the beginning of the existing range then a new file will be created and the existing file will be appended to the new one.

`.metadata` will store the tree which is used to find ranges. 


```
file.extend_with(other: File)

pub fn extend_with(&mut self, other: File);