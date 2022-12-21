# ActuallyDumpThatLSASS - Fixed and polished code so other researchers don't have to.
## ~~It's Fully Undetectable and bypass almost all the vendors AV/EDRs, it doesn't bypass RunAsPPL~~ It's not Fully Undetectable and doesn't bypass all AV/EDRs.
## Dumping LSASS by Unhooking `MiniDumpWriteDump` and possibly other hooks by getting copies of multiple libraries from the disk and using them to overwrite images loaded in memory, plus functions and strings obfuscation *(this time actually done correctly)*, duplicate LSASS handle.
## The execution may take time, bcz of ~~sandboxing check~~ enumeration of all processes.


![MiniLSASS](https://user-images.githubusercontent.com/110354855/192168199-1dec54ff-fbf9-4d20-b407-0408e9f38ba4.png)


![DumpThatLsass](https://user-images.githubusercontent.com/110354855/192162544-f49a10a5-1b6d-42af-98e5-e3d2117dc09d.png)
