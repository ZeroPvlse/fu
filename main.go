package main

import (
	"fmt"
	"os"
	"strings"
)

type Token string
type Tokens []Token

// i love my tokens
const (
	READ  Token = "read"
	WRITE Token = "write"
	LOOP  Token = "token"
	EXEC  Token = "exec"
)

// man my sweet sweet tokens
var ValidTokens = Tokens{READ, WRITE, LOOP, EXEC}

const (
	ErrInvalidArgUsage int = iota + 1
	ErrReadFromFile
)

func init() {
	if err := canFuckignRun(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "err: %v\n", err)
		os.Exit(ErrInvalidArgUsage)

	}
}

func main() {

	// we can use it safely :3
	filename := os.Args[1]

	// file <-
	_, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "err: %v\n", err)
		os.Exit(ErrReadFromFile)
	}

	// read file from top to bottom
	// 		check if token is there
	//			if not FUCKING THROW error or if
	//			else check if WE CAN EVEN EXECUTE SOMETHING if not
	// 					GUESS WHAT -> THORW FUCKING ERROR! (man i love em)
	// 			and then finally EXECUTE WHATEVER THE FUCKKK IS THEREEE (fuck consequences)
	//					IF WE CAN'T? 	THROW AN ERROR! THROW AN ERROR!!!!!!!
	//
	//	if EOF -> gracefully thank user for cooperation :4

}

// fuck you all
func canFuckignRun(args []string) error {

	if len(os.Args) < 2 || len(os.Args) > 2 {
		return fmt.Errorf("damn dumbass use\njust write 'fuckoff [filename.fu]'")

	}

	if strings.HasSuffix(args[1], ".fu") {
		return fmt.Errorf("bruv pass file with '.fu' suffix")
	}

	return nil

}

func Tokenizer(lines []string) (map[Token]string, error) {

	//					2d array?
	// LINES{[word1, word2], [word1, word2]}
	tokWVal := make(map[Token]string)

	for i, line := range lines {
		lineTok := strings.Fields(line)
		if tok, ok := isToken(lineTok[0]); !ok {
			return nil, fmt.Errorf("%d: contains invalid token %s \n", i, tok)
		} else {
			// if there are some psychos outta here who like writing using uppercase
			//				 |
			// this is for u v fucking SQL psychos
			tokWVal[tok] = strings.ToLower(lineTok[0])
		}

	}

	return nil, nil

}

func isToken(word string) (Token, bool) {
	for _, tok := range ValidTokens {
		if word == string(tok) {
			return tok, true
		}

	}
	return "", false
}
