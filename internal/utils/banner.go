package utils

import (
	"fmt"
	"strings"
)


const bannerArt = `

_____               _       _        
| ____|___  ___ __ _| | __ _| |_ ___  
|  _| / __|/ __/ _| | |/ _| | __/ _ \ 
| |___\__ \ (_| (_| | | (_| | || (_) |
|_____|___/\___\__,_|_|\__,_|\__\___/ 
									  
`


func DisplayBanner(){
	fmt.Println(strings.TrimSpace(bannerArt))
	fmt.Println()
	fmt.Println("IAM Security Auditing Tool by Patryk Zawieja")
	fmt.Println("--------------------------------------------")
}