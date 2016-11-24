#include <stdio.h>
#include <string.h>
int main(int argc,char *argv[])
{
	char name[]="helloworld";
	int  keys[]={0xb,0x1f,0x19,0x19,0x49,0xb,0xb,0xb,0x31,0x53};
	char Thekeys[11];
	int i;
	for(i=0;i<10;i++)
	{
		keys[i]^=7;
		keys[i]=keys[i]/6;
		keys[i]+=22;
		keys[i]-=24;
		keys[i]^=name[i];
	}
	for(i=0;i<10;i++)
	{
		Thekeys[i]=keys[i];
	}
	Thekeys[i]=0;
	if(!strcmp(Thekeys,argv[1]))
		printf("Good Work,you have Successed!");
	else
		printf("NO,you are failed!");
	return 0;
}
