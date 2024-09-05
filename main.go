package main

import (
	"fmt"
	"os"
	"strings"
	//"strconv"
	//"slices"

	peparser "github.com/saferwall/pe"
)

const (
	ImageSectionCntUninitializedData = "Unitialized Data"
	ImageSectionCntInitializedData   = "Initialized Data"
	ImageSectionCntCode              = "Contains Code"
	ImageSectionMemRead              = "Readable"
	ImageSectionMemWrite             = "Writable"
	ImageSectionMemDiscardable       = "Discardable"
	ImageSectionMemExecute           = "Executable"
	ImageSectionLnkInfo              = "Lnk Info"
	ImageSectionGpRel                = "GpReferenced"
)

// StandardSections Variable is the actual Standard that Microsoft details here: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
var StandardSections = map[string][]string{
	".bss": {
		ImageSectionCntUninitializedData,
		ImageSectionMemRead,
		ImageSectionMemWrite,
	},
	".cormeta": {
		ImageSectionLnkInfo,
	},
	".data": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemWrite,
	},
	".debug$F": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemDiscardable,
	},
	".debug$P": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemDiscardable,
	},
	".debug$S": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemDiscardable,
	},
	".debug$T": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemDiscardable,
	},
	".drective": {
		ImageSectionLnkInfo,
	},
	".edata": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
	},
	".idata": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemWrite,
	},
	".idlsym": {
		ImageSectionLnkInfo,
	},
	".pdata": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
	},
	".rdata": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
	},
	".reloc": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemDiscardable,
	},
	".rsrc": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
	},
	".sbss": {
		ImageSectionCntUninitializedData,
		ImageSectionMemRead,
		ImageSectionMemWrite,
		ImageSectionGpRel,
	},
	".sdata": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemWrite,
		ImageSectionGpRel,
	},
	".srdata": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionGpRel,
	},
	".sxdata": {
		ImageSectionLnkInfo,
	},
	".text": {
		ImageSectionCntCode,
		ImageSectionMemExecute,
		ImageSectionMemRead,
	},
	".tls": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemWrite,
	},
	".tls$": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemWrite,
	},
	".vsdata": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
		ImageSectionMemWrite,
	},
	".xdata": {
		ImageSectionCntInitializedData,
		ImageSectionMemRead,
	},
}

func parseFile(filePath string) *peparser.File {

	pe, err := peparser.New(filePath, &peparser.Options{})
	if err != nil {
		panic(fmt.Sprintf("Error while opening file: %s, reason: %v", filePath, err))
	}

	pe.Parse()
	return pe
}

func checkSectionsStandard(sectionName string, sectionFlags []string) {

	if values, ok := StandardSections[sectionName]; ok {
		for _, flag := range sectionFlags {
			exist := false
			for _, val := range values {
				if flag == val {
					exist = true
					break
				}
			}
			if !exist {
				fmt.Printf("\t\tNon standard characteristic found, got '%s'.\n", flag)
			} else {
				fmt.Printf("\t\t%s\n", flag)
			}
		}
	} else {
		fmt.Printf("\t\tNon standard section found.\n\t\tCharacteristics: %+v\n", sectionFlags)
	}
}

// printHeaders Function simply prints imports in a nice way, i should make one that generate a csv output to be simpler to parse out
// need to parse header data to recognise packers and so on
func printHeaders(pe *peparser.File) {

	fmt.Printf("HEADERS:\n\n")

	if pe.FileInfo.HasDOSHdr {
		fmt.Printf("\tDOS Header:\n\t\t%v\n\n", pe.DOSHeader)
	} else {
		fmt.Printf("\tDOS Header:\n\t\tDOS Header is empty !\n\n")
	}
	if pe.FileInfo.HasRichHdr {
		fmt.Printf("\tRich Header:\n\t\t%v\n\n", pe.RichHeader)
	} else {
		fmt.Printf("\tRich Header:\n\t\tRich Header is empty !\n\n")
	}
	if pe.FileInfo.HasNTHdr {
		fmt.Printf("\tNT Header:\n\t\t%v\n\n", pe.NtHeader)
	} else {
		fmt.Printf("\tNT Header:\n\t\tNT Header is empty !\n\n")
	}
}

// printCOFF Function simply prints imports in a nice way, i should make one that generate a csv output to be simpler to parse out
func printCOFF(pe *peparser.File) {
	if pe.FileInfo.HasCOFF {
		fmt.Printf("COFF:\n\n")
		// maybe implement this to be pretty printed
		fmt.Printf("\t%v\n\n", pe.COFF)
	} else {
		fmt.Printf("COFF:\n\tsymbol table is empty !\n\n")
	}
}

// printSections Function simply prints imports in a nice way, i should make one that generate a csv output to be simpler to parse out
func printSections(pe *peparser.File) {
	if pe.FileInfo.HasSections {
		fmt.Printf("SECTIONS:\n\n")
		for _, sec := range pe.Sections {
			flags := sec.PrettySectionFlags()

			fmt.Printf(
				"\t%s\n",
				strings.TrimRight(
					fmt.Sprintf("%s", sec.Header.Name),
					"\x00"))

			s := strings.TrimRight(fmt.Sprintf("%s", sec.Header.Name), "\x00")

			checkSectionsStandard(s, flags)

		}
	} else {
		fmt.Printf("SECTIONS:\tNo section found in the file !\n\n")
	}
}

func getFunctions(pe *peparser.File) (map[string][]string, error) {
	if pe.FileInfo.HasImport {
		impMap := make(map[string][]string, 0)
		for _, imp := range pe.Imports {
			for _, fn := range imp.Functions {
				impMap[imp.Name] = append(impMap[imp.Name], fn.Name)
			}
		}
		return impMap, nil
	} else {
		return nil, fmt.Errorf("\nIMPORTS:\tNo Import found in the file !\n\n")
	}
}

// printImports Function simply prints imports in a nice way, i should make one that generate a csv output to be simpler to parse out
func printImports(imps map[string][]string) {
	fmt.Printf("IMPORTS:\n")
	for lib, fun := range imps {
		fmt.Printf("\n\tLIBRARY: %s", lib)
		for _, fn := range fun {
			fmt.Printf("\n\t\t%s", fn)
		}
		fmt.Printf("\n")
	}
}

func main() {

	var files []string = os.Args[1:]

	for _, f := range files {

		fmt.Printf("\nFILE:\t%s\n\n", f)

		peFile := parseFile(f)

		printSections(peFile)

		printHeaders(peFile)

		printCOFF(peFile)

		impMap, err := getFunctions(peFile)
		if err != nil {
			fmt.Printf("%s", err)
		} else {
			printImports(impMap)
		}
	}
	fmt.Println()
}
