#!/usr/bin/python
import sys
import re
import argparse

def xorCript(str1,str2):
	return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(str1,str2))

def stringXor(xoredStr,word):    
    results = []
    result = ''
    word_len = len(word)
    pos = len(xoredStr)-word_len+1
    for index in xrange(pos):
        result = ''
        for a,b in zip(xoredStr[index:index+word_len],word):
            result += chr(ord(a) ^ ord(b))
        results.append(result)
    return results

def displayLine(text):
    line_width = 140
    text_len = len(text)
    for chunk in xrange(0,text_len,line_width):
        if chunk > text_len-line_width:
            print str(chunk) + chr(9) + text[chunk:]
        else:
            print str(chunk) + chr(9) + text[chunk:chunk+line_width]


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('c1', help='Primeira cifra')
	parser.add_argument('c2', help='Segunda cifra')
	parser.add_argument('-w',dest='wordlist', help='dicionario',default=None,required=False)
	# parser.add_argument('-k',dest='key', help='Texto plano de uma das mensagens',default=None,required=False)
	args = parser.parse_args()
	
	try:
		cipher1 = open(args.c1,"r").readline().strip("\n")
		cipher2 = open(args.c2,"r").readline().strip("\n")
	except:
		print "Erro ao abrir os arquivos que contem as cifras"
		exit(-1)
	xoredStr = xorCript(cipher1.decode('hex'),cipher2.decode('hex'))

	xoredStr_len = len(xoredStr)
	displayMensage1 = "_" * xoredStr_len
	displayMensage2 = "_" * xoredStr_len
	charset = '^[a-zA-Z]+$'	
	response = ''
	if args.wordlist:
		try:
			wordlist = open(args.wordlist,"r").readlines()
		except:
			print "Erro ao abrir o dicionario"
			exit(-1)
		for word in wordlist:
			results = stringXor(xoredStr,word.strip("\n"))
			for r in results:
				if (re.search(charset,r)):
					print word.strip("\n")+" -> "+r
		exit(0)
	while response != 'fim':
		print "Mensagem atual:"
		displayLine(displayMensage1)
		print "Chave atual:"
		displayLine(displayMensage2)
		word = raw_input("Informe uma string: ")
		word_len = len(word)	
		results = stringXor(xoredStr, word)
		results_len = len(results)
		for result_index in xrange(results_len): 
	            if (re.search(charset,results[result_index])):
			    print '[+] ' + str(result_index) + ': "' + results[result_index] + '"'
	            else:
			    print '[-] ' + str(result_index) + ': "' + results[result_index] + '"'
	
		response = raw_input("Informe a posicao, 'enter' para nenhuma correspondencia, ou 'fim' para encerrar: ")
		try:
			response = int(response)
			if (response < results_len):
				message_or_key = ''
				while (message_or_key != '1' and message_or_key != '2'):
					message_or_key = raw_input("Essa palavra faz parte da mensagem1 ou da mensagem2? Informe '1' ou '2' (mensagem1/,mensagem2): ")
					if(message_or_key == '1'):
						displayMensage1 = displayMensage1[:response] + word + displayMensage1[response+word_len:]
						displayMensage2 = displayMensage2[:response] + results[response] + displayMensage2[response+word_len:]
					elif(message_or_key == '2'):
						displayMensage2 = displayMensage2[:response] + word + displayMensage2[response+word_len:]
						displayMensage1 = displayMensage1[:response] + results[response] + displayMensage1[response+word_len:]
					else:
						print 'Tente novamente.'
	
		except ValueError:
			if (response == 'fim'):
				print "Sua mensagem 1 eh: " + displayMensage1
				print "Sua mensagem 2 eh: " + displayMensage2
			else:
				print "Entrada invalida."
	
if __name__ == '__main__':
	main()
