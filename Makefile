CC=gcc

CFLAGS = -I/usr/include/openssl
LDFLAGS=-lcrypto 

OBJS=lex.yy.o y.tab.o base64.o

sqlsig: ${OBJS}
	${CC} -o sqlsig ${OBJS} ${LDFLAGS}

%.o: %.c
	${CC} -c ${CFLAGS} -o $@ $<

lex.yy.c: sql.l y.tab.h
	lex sql.l

y.tab.c y.tab.h: sql.y
	yacc -d sql.y

clean:
	rm -f ${OBJS} lex.yy.c y.tab.c y.tab.h sqlsig
