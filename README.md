# catpe - simple pe analzyer 
Simple and Lightweight PE Analyzer  


## why
l'm building this project as the pratical part of my study of the Portable Executable (PE) file format :D 

## usage
### install by pip
```shell
pip intall catpe
```

### use
```shell
catpe --target="<file>.exe" 
``` 
if you prefer,you can use the "-t" shorthand instenad of "--target"
### output
```catpe output exemple
file: ../crackme-solutions/crackMeOnePatched.exe
------------------
mz header:ok
offset: 256
machine: 0x14c
sessions number: 6
timetamp: 1523808755
------------------
Tamanho do arquivo: 1986048
e_lfanew: 0x100
Assinatura: b'PE\x00\x00'
Bytes hex: 50450000
```

