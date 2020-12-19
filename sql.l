%{
#include "y.tab.h"
%}

alpha [a-zA-Z]
digit [0-9]
%%
[ \t]			{}
[ \n]   		{}
select		return SELECT;
SELECT		return SELECT;
create		return CREATE;	
CREATE		return CREATE;
drop		return DROP;
DROP		return DROP;
table 		return TABLE;
TABLE		return TABLE;
distinct	return DISTINCT;
DISTINCT	return DISTINCT;
from            return FROM;
FROM		return FROM;
where           return WHERE;
WHERE		return WHERE;
like            return LIKE;
LIKE		return LIKE;
desc            return DESC;
DESC		return DESC;
asc             return ASC;
ASC		return ASC;
grant 		return GRANT;
GRANT		return GRANT;
on 		return ON;
ON		return ON;
to 		return TO;
TO		return TO;
revoke		return REVOKE;
REVOKE		return REVOKE;
"group by"	return GROUP;
"GROUP BY"	return GROUP;
having          return HAVING;
HAVING		return HAVING;
"order by"	return ORDER;
"ORDER BY"	return ORDER;
or		return OR;
OR		return OR;
and		return AND;
AND		return AND;
insert 		return INSERT;
INSERT		return INSERT;
into		return INTO;
INTO		return INTO;
values 		return VALUES;
VALUES		return VALUES;
update      	return UPDATE;
UPDATE		return UPDATE;
delete 		return DELETE;
DELETE		return DELETE;
set         	return SET;
SET	     	return SET;
varchar   	return DT;
VARCHAR		return DT;
number 		return DT;
NUMBER		return DT;
float 		return DT;
FLOAT		return DT;
{digit}+	return NUM;
{alpha}({alpha}|{digit})* return ID;
"<="            return LE;
">="            return GE;
"=="            return EQ;
"!="            return NE;
";"	        return COL;
.               return yytext[0];
%%
