package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// HTMLファイルを解析して必要な項目のみ表示
func main() {
	var infoRow, cvssBaseScore, riskFactor, pluginOutput, synopsis, description, solution, title string
	fileList := dirwalk("./html")
	for i := 0; i < len(fileList); i++ {
		fmt.Println(fileList[i])
		filename := fileList[i]
		ipFlg := false
		synopsisFlg := false
		descriptionFlg := false
		solutionFlg := false
		riskFactorFlg := false
		cvssBaseScoreFlg := false
		pluginOutputFlg := false
		displayFlg := false

		fp, err := os.Open(filename)
		if err != nil {
			fmt.Println("file read error")
			return
		}
		defer fp.Close()
		scanner := bufio.NewScanner(fp)

		for scanner.Scan() {
			if ipFlg {
				ip := removeTag(scanner.Text())
				if ip != "" {
					fmt.Println(ip)
					ipFlg = false
				}
			}
			if strings.Contains(scanner.Text(), "IP:") {
				ipFlg = true
			}
			if strings.Contains(scanner.Text(), "background: #0071b9; font-weight: bold;") {
				displayFlg = false
				continue
			} else if strings.Contains(scanner.Text(), "background: #d43f3a; font-weight: bold;") || strings.Contains(scanner.Text(), "background: #ee9336; font-weight: bold;") || strings.Contains(scanner.Text(), "background: #fdc431; font-weight: bold;") || strings.Contains(scanner.Text(), "background: #3fae49; font-weight: bold;") {
				title = removeTag(scanner.Text())
				infoRow = ""
				displayFlg = true
			}
			if displayFlg {
				if synopsisFlg {
					synopsis = removeTag(scanner.Text())
					if synopsis != "" {
						synopsisFlg = false
					}
				}
				if strings.Contains(scanner.Text(), "Synopsis") {
					synopsisFlg = true
				}
				if descriptionFlg {
					description = removeTag(scanner.Text())
					if description != "" {
						descriptionFlg = false
					}
				}
				if strings.Contains(scanner.Text(), "Description") {
					descriptionFlg = true
				}
				if solutionFlg {
					solution = removeTag(scanner.Text())
					if solution != "" {
						solutionFlg = false
					}
				}
				if strings.Contains(scanner.Text(), "Solution") {
					solutionFlg = true
				}
				if riskFactorFlg {
					riskFactor = removeTag(scanner.Text())
					if riskFactor != "" {
						riskFactorFlg = false
					}
				}
				if strings.Contains(scanner.Text(), "Risk Factor") {
					riskFactorFlg = true
				}
				if cvssBaseScoreFlg {
					cvssBaseScore = removeTag(scanner.Text())
					cvssBaseScore = removeCvssDetail(cvssBaseScore)
					if cvssBaseScore != "" {
						cvssBaseScoreFlg = false
					}
				}
				if strings.Contains(scanner.Text(), "CVSS Base Score") {
					cvssBaseScoreFlg = true
				}
				if pluginOutputFlg {
					pluginOutput = removeTag(scanner.Text())
					pluginOutput = removeCvssDetail(pluginOutput)
					if pluginOutput != "" {
						infoRow = cvssBaseScore + "\t" + riskFactor + "\t\t" + pluginOutput + "\t\t" + synopsis + "\t" + description + "\t" + solution + "\t" + title
						fmt.Println(infoRow)
						cvssBaseScore = ""
						riskFactor = ""
						pluginOutput = ""
						synopsis = ""
						description = ""
						solution = ""
						title = ""
						pluginOutputFlg = false
					}
				}
				if strings.Contains(scanner.Text(), "Plugin Output") {
					pluginOutputFlg = true
				}
			}
		}
		if err = scanner.Err(); err != nil {
			fmt.Println("file scan error")
			return
		}
	}
}

// HTMLタグ削除
func removeTag(str string) string {
	rep := regexp.MustCompile(`<("[^"]*"|'[^']*'|[^'">])*>`)
	str = rep.ReplaceAllString(str, "")
	return str
}

// ()書きの情報削除
func removeCvssDetail(str string) string {
	rep := regexp.MustCompile(`\(("[^"]*"|'[^']*'|[^'">])*\)`)
	str = rep.ReplaceAllString(str, "")
	return str
}

// htmlフォルダ内検索
func dirwalk(dir string) []string {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		panic(err)
	}

	var paths []string
	for _, file := range files {
		paths = append(paths, filepath.Join(dir, file.Name()))
	}

	return paths
}
