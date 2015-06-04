# Rafael Reverse Engineering Challenge Level 3

Rafael Advanced Defense Systems Ltd is an Israeli defense technology company. It was founded as Israel’s National R&D Defense Laboratory for the development of weapons and military technology within the Ministry of Defense.
Rafael develops and produces weapons, military, and defense technologies for the Israel Defense Forces and for export abroad.

Rafael are looking to hire reverse engineers and created this series of binary challenges, the winner will be rewarded in a flight ticket (hotel and free entrance) to the BlackHat Conference. 

![alt tag](http://portal.rafael.co.il/rechallenge15/Documents/rechallenge15/img/compatition.jpg)

# Level 3

When you proceed to stage2 (level 1 is stage0.exe) you receive a PE file named ```stage2.exe```. 

First run: 

![alt tag](http://oi57.tinypic.com/2s9dcgg.jpg)

As you can see the program is expecting you to provide a correct password in order to give you the email address.

# Jumping in. 

the first function:

![alt tag](http://oi62.tinypic.com/33lgrk0.jpg)

Or, translated to C language, in short:

```c
printf("Enter password:");
fgets(buf, 79, stdin);
func = f4028B0(0x5F048AF0);
func(0x402450);
```

As you can see the function asks for a password and right after that it dynamically calculate an address for it to call with an hardcoded argument.
Which revealed to be the ```SetUnhandledExceptionFilter```  - a WINAPI function, the function's description from MSDN:

> Enables an application to supersede the top-level exception handler of each thread of a process.

> After calling this function, if an exception occurs in a process that is not being debugged, and the exception makes it to the unhandled exception filter, that filter will call the exception filter function specified by the lpTopLevelExceptionFilter parameter.

So, that means, as you can alreaday tell - the program sets the address ```0x402450``` as the function to be called if an exception occurs && the program is not being debugged.

Okay, your is guess right - this is an anti-debugging technique. 
if we'll continue stepping the program - we'll eventually exit the program. 

> **By the way, if you're debugging the program using [OllyDBG](http://ollydbg.de) and you see the crtlib functions and other functions as functions in the address-space of the program its because the program is statically linked. which makes it annoying to debug..**

Let's continue, so as we figured out - we need to enter this function (at ```0x402450```) you can use any olly plugins to get around it or even patch the program to call ```0x402450``` directly after getting the user input.

# 0x402450

This function is basically the `main` code of the crackme, this is what we need to examine: 

![alt tag](http://oi60.tinypic.com/35l94jm.jpg)

Translated to C language (easier to understand): 

```c
void f402450() {
	char res1, res2;
	unsigned int i;
	FILE *fp;
	HMODULE libload;

	fp = fopen("tmp0.X", "wb");
	if (!fp) {
		exit(0);
	}
	for (i = 0; i < 7168; ++i) {
		if (fp) {
			v2 = stalin1(blobdata[i], input[0], input[1], input[2], input[3]); //402650
			fputc(v2, fp);
		}
		else {
			v1 = stalin2(blobdata[i], input[0], input[1], input[2], input[3]); //4026F0
			fputc(v1, 0);
		}
	}
	fclose(fp);
	func_ptr_1 = f4028B0(0xA498EAB6); 
	func_ptr_1(1); //kernel32.SetErrorMode(1)
	
	func_ptr_2 = f4028B0(0xEC0E4E8E);
	libload = func_ptr_2("tmp0.X"); //kernel32.LoadLibraryA("tmp0.X")
	
	func_ptr_3 = f4028B0(0x7C0DFCAA); //GetProcAddress
	
	remove("tmp0.X");
	
	if (libload) {
		qualify_ptr = func_ptr_3(libload, "qualify"); //kernel32.GetProcAddress(libload, "qualify")
		if (qualify_ptr) {
			if (qualify_ptr("User1234", 8, &(restinput+4), strlen(&(restinput+4))) == false) {
				qqqq(&(restinput+4));
				exit(1);
			}
		}
	}
	printf("Wrong...");
	exit(1);
}
```
So as you can see, after looking at the beautiful looking C code... the following happens: 

1. A handle for a filename ```tmp0.X``` in ```wb``` mode
2. There's a loop that does some operations (inside ```stalin1``` & ```stalin2```, we'll get to it) on our input, combined with a blob data for **7168** times
3. Then the file is closed and a pointer to ```SetErrorMode``` function is dynamically generated and then calls it with the parameter '1' in order to hide errors from the user.
4. And then the program attempts to dynamically load (using ```LoadLibraryA```) the file ```tmp0.X``` and grabbing a pointer to the function ```GetProcAddress```.
5. After that the file ```tmp0.X``` is deleted and (in short) the program attempts to call a function named ```qualify``` from tmp0.X.

> I'm saving you the explanation about which functions does what and how the functions are dynamically generated because it's long and not interesting.

# Meet Stalin

This function does the operation (from section 2) on our input combined with the ```blobdata```, remember? 

![alt tag](http://oi59.tinypic.com/15gbfpj.jpg)

And as a convert to C: 

```c
int stalin1(int blobdata_pos, int input1, int input2, int input3, int input4) {
  return input1 ^ ((12 * (((input3 * input3 ^ 5) * input3 - 3) + 4 - (input3 * input3 ^ 5))
              + 4 * (blobdata_pos - input1)
              - 3 * (16 - 4 * (input3 * input3 ^ 5) + 4 * ((input3 * input3 ^ 5) * input3 - 3))
              - 4 * input4)
             / 12
             + 32);
}
```

Yep, it is what it is... 

# Okay.. so what do we have to do ?

As we mentioned above, the program takes our input combined with some blob data of its own and creates the tmp0.X file that supposed to be a shared object AKA DLL in windows, right ?

sounds like a mess right ? 

there's a simple solution for it.. our input should be something that creates a DLL right ? so what we have to do is check which input will make stalin1 output ```0x4d5a9000``` for the first four iterations.

think about it? why ```0x4d5a9000``` ? right, because this is the DLL first-four-bytes header ('M' 'Z' 0x90 0x00 as you know it).

Those with sharp eyes already noticed that the second and third bytes of our input doesnt affect the output of stalin1, so its even easier!

This code should do the job: 

```C
int stalin1(int blobdata_pos, int input1, int input2, int input3, int input4) {
  return input1 ^ ((12 * (((input3 * input3 ^ 5) * input3 - 3) + 4 - (input3 * input3 ^ 5)) + 4 * (blobdata_pos - input1) - 3 * (16 - 4 * (input3 * input3 ^ 5) + 4 * ((input3 * input3 ^ 5) * input3 - 3)) - 4 * input4) / 12 + 32);
}



int main() {
	for (int j = 33; j < 122; j++) {
		for (int i = 33; i < 122; i++) {
			if (stalin1(0x181, j, 33, 33, i) == 0x5a && stalin1(0x142, j, 33, 33, i) == 0x4d && stalin1(0x223, j, 33, 33, i) == 0x90 && stalin1(0x73, j, 33, 33, i) == 0x00) {
				printf("input1:0x%x input44:0x%x\n", j, i);
			}
		}
	}
	return 0;
}
```

> if thats not clear enough, ```0x181```, ```0x142```, ```0x223``` and ```0x73``` are the content of the first four blobdata_pos arguments.

so after we have the correct combination in order to correctly create the DLL, what's next ? debugging the qualify function!

![alt tag](http://oi61.tinypic.com/ww1cap.jpg)

This is how the ```qualify``` function look like.. 

Because this is already too long, what basically happens inside the third function call from qualify is comparison of input+4 and 2740310433063552.

So if you got all things correctly your password should be 

```
$[1][2]C2740310433063552
```

Which leads to: 

![alt tag](http://oi61.tinypic.com/2wbs55s.jpg)

I hope you enjoyed, this was one of the most interesting crackme's i've ever done ;)
