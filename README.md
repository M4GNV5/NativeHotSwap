#NativeHotSwap

Tool for changing the code of native programs during runtime

Take a look at the [demo video](https://i.m4gnus.de/tanaro.mp4)

Special thanks to @maddinat0r for the idea

##How this works
- at program start it parses all `.o` files in the same directory as your executable
- it hashes all functions that are in the `.o` files
- it associates all hashed functions with addresses by parsing the executable itself
- it waits for a change in any of the `.o` files
- if a function in any of the `.o` files changes (i.e. it hash changes) 
	- it imports the new code
	- it links the new code against the old symbol positions (actually TODO)
	- it changes the first instruction of the old code to `jmp <new code>`
