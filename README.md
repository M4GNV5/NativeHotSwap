#NativeHotSwap

Tool for changing the code of native programs during runtime

Take a look at the [demo video](https://i.m4gnus.de/tanaro.mp4)

Special thanks to @maddinat0r for the idea

##How this works
- You link your code with `-q` (for gcc `-Wl,-q`)
- at program start it hash all functions that are in your executable
- it waits for any changes to your executable file
- if a function in the executable files changes (i.e. it hash changes)
	- it imports the new code
	- it links the new code against the old symbol positions (this is TODO)
	- it changes the first instruction of the old code to `jmp <new code>`
