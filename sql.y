
%{

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/sha.h>
#include "base64.h"

#define MAX_SIG_LINE	32

void tack_sig_txt(char *in);
void tack_sig(int in);
void sig_dump(void);
void sig_start(void);

char *plaintxt;
int plaintxt_len;

%}


%token SELECT DISTINCT FROM WHERE LE GE EQ NE OR AND LIKE GROUP HAVING ORDER ASC DESC 
%token INSERT INTO VALUES
%token UPDATE SET
%token CREATE TABLE DROP DELETE DT ID NUM  COL
%token GRANT ON TO REVOKE

%right '='
%left AND OR
%left '<' '>' LE GE EQ NE

%start program
%%

program		: S COL program { tack_sig(0); }
			| S error COL program { tack_sig(1);}
			| S COL { tack_sig(2); }	
			| S     { tack_sig(100); } /* last minute change */
			| error { tack_sig(3); }
			;
	

S			: ST1  { tack_sig(4); }
			| ST11 { tack_sig(5); }
			| ST12 { tack_sig(6); }
			| ST13 { tack_sig(7); } 
			| ST14 { tack_sig(8); } 
			| ST15 { tack_sig(9); } 
			| ST16 { tack_sig(10);}
			| ST17 { tack_sig(11);}
			;

 
	ST1    :  CREATE TABLE tablename '('newList')' {tack_sig(12);}
			| CREATE error { tack_sig(-1); }
		;


	ST11	: SELECT attributeList FROM tablename ST2 {tack_sig(13); }
			| SELECT DISTINCT attributeList FROM tableList ST2 {
			 tack_sig(14);
			} 
			| SELECT attributeList error { tack_sig(-2); }
			| SELECT attributeList FROM error { 
		          tack_sig(-3);
			}
		;	


	ST12	: INSERT INTO tablename VALUES '('attributeList')' {
		   tack_sig(15);
		  }
			| INSERT INTO tablename '('coloumnList')' VALUES '('attributeList')' {
			 tack_sig(16);
			}
			| INSERT error { tack_sig(-4); }
			| INSERT INTO tablename error { tack_sig(-5); }


			;

	ST13	: UPDATE tablename SET ECOND WHERE ECOND { tack_sig(17); }
	 		| UPDATE error { tack_sig(-6); }
	 		| UPDATE tablename error { tack_sig(-7); }
	 		| UPDATE tablename SET error { tack_sig(-8); }
			;

	ST14	:  DELETE attributeList FROM tablename ST2 { tack_sig(18); }
			| DELETE FROM tablename ST2 {tack_sig(19); }
	 		| DELETE attributeList error { tack_sig(-9); }
	 		| DELETE error { tack_sig(-10); }
	 		| DELETE attributeList FROM error { tack_sig(-11); }

			;

	ST15	: DROP TABLE tablename { tack_sig(20); } 
	 		| DROP error { tack_sig(-12); }
	 		| DROP TABLE error { tack_sig(-13); }
			;
			
	ST16 : GRANT privilege_name ON tableList TO username { tack_sig(21); }
    		| GRANT error { tack_sig(-14); }
			;
			
	ST17 : 	REVOKE privilege_name ON tableList FROM username { 
		 tack_sig(22);
		}
		 	| REVOKE error { tack_sig(-15); }

			;

    ST2     : WHERE COND ST3 {tack_sig(23); }
               | ST3	     {tack_sig(24); }
               ;
    ST3     : GROUP attributeList ST4 {tack_sig(25);}
               | ST4 {tack_sig(26); }
               ;
    ST4     : HAVING COND ST5 {tack_sig(27);}
               | ST5          {tack_sig(28);}
               ;
    ST5     : ORDER attributeList ST6 {tack_sig(29); }
               |
               ;
    ST6     : DESC {tack_sig(30);}
               | ASC {tack_sig(31); }
               |
               ;

newList 	: ID DT'('NUM')' {tack_sig(32); }
			| ID DT'('NUM')'','newList {tack_sig(33); }
			; 
    
attributeList : ID','attributeList  { tack_sig(34); }
  		| NUM',' attributeList {tack_sig(35); }
  		| ID {tack_sig(37);}
		| NUM {tack_sig(37); }
		|'"'attributeList'"' {tack_sig(38);}
		| '"'attributeList'"'','attributeList {tack_sig(39); }
        	| '*' {tack_sig(40); }
		;

tableList    : ID',' tableList {tack_sig(41); }
               | ID {tack_sig(42); }
               ;

coloumnList :  ID','coloumnList {tack_sig(43); }
		| ID { tack_sig(44); }
		; 

tablename : ID {tack_sig(45);}
		;

COND    : COND OR COND {tack_sig(46); }
               | COND AND COND {tack_sig(47); }
               | E {tack_sig(48); }
               ;

ECOND  : ECOND','G {tack_sig(49); }
		| G {tack_sig(50); }
		; 

username : ID {tack_sig(51); }
		| ID','username {tack_sig(52); }
		;

privilege_name : ID {tack_sig(53); }
			| ID',' privilege_name {tack_sig(54); }
			| '*' {tack_sig(55); }
			;
			
E         : F '=' F {tack_sig(56); }
	       | F '=''"'F'"' {tack_sig(56);}
               | F '=''\''F'\'' { tack_sig(102); }
               | F '<' F {tack_sig(57);}
               | F '>' F {tack_sig(58);}
               | F LE F {tack_sig(59); }
               | F GE F {tack_sig(60); }
               | F EQ F {tack_sig(61); }
               | F NE F {tack_sig(62); }
               | F OR F {tack_sig(63); }
               | F AND F {tack_sig(64); }
               | F LIKE F {tack_sig(65); }
               ;

G		: F '=' F { tack_sig(66); }
		| F '=''"'F'"' { tack_sig(67); }
		| F '=''\''F'\'' { tack_sig(101); }
		;

F       : ID {tack_sig(68);}
		| NUM {tack_sig(69);}
		;




%%
#include <ctype.h>

int main(int argc, char *argv[]) {

 sig_start();
 tack_sig_txt("SQL:");
 yyparse();
 sig_dump();
   return 0;
}          

void tack_sig_txt(char *in) {
 char *j;
 int i, l;
 l = strlen(in);
 plaintxt = (char *)realloc(plaintxt, plaintxt_len+l);
 if(!plaintxt) {
  perror("realloc");
  exit(0);
 }
 j = &plaintxt[plaintxt_len];
 plaintxt_len+=l;
 for(i=0;i<l;i++) 
  j[i] = in[i];
}

void tack_sig(int in) {
 char line[MAX_SIG_LINE];
 snprintf(line, MAX_SIG_LINE, "%d:", in);
 tack_sig_txt(line);
}

void sig_start(void) {
 plaintxt_len = 0;
 plaintxt = NULL;
}

void out64(char in) {
 putchar(in);
}

void sig_dump(void) {
 SHA256_CTX c;
 int i;
 unsigned char  hash[SHA256_DIGEST_LENGTH];

 SHA256_Init(&c);
 SHA256_Update(&c, plaintxt, plaintxt_len);
 SHA256_Final(hash, &c);

 base64_reset();
 base64_wrap = 9000; // high number that we don't reach
 base64_out64_callback=out64;

 for(i=0;i<SHA256_DIGEST_LENGTH;i++) {
  base64_outbyte(hash[i]);
 }
 base64_outbyte(-1);
 putchar('\n');
}

yyerror(char *s) {
}

yywrap(){
}
