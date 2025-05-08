/*
 This file has implementation of the main banner for the tool. It is used in cmd/root.go
*/
package utils

import (
	"fmt"
	"strings"
	"github.com/fatih/color"
)


const bannerArt = `

_____               _       _        
| ____|___  ___ __ _| | __ _| |_ ___  
|  _| / __|/ __/ _| | |/ _| | __/ _ \ 
| |___\__ \ (_| (_| | | (_| | || (_) |
|_____|___/\___\__,_|_|\__,_|\__\___/ 
									  
`


func DisplayBanner(){
	color.Magenta(strings.TrimSpace(bannerArt))
	fmt.Println()
	fmt.Println("IAM Security Auditing Tool by Patryk Zawieja")
	fmt.Println("--------------------------------------------")
}