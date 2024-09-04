package main

import (
	"fmt"
	"os"
    "strings"
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

func checkSectionsStandard(sectionName string) { //, sectionFlags []string) {

    for key, values := range StandardSections {
        if check := strings.Compare(sectionName, key); check == 0 {
            fmt.Println(values)
        } else {
            fmt.Printf("sectionName: '%s'\ttype: '%T'\tkey: '%s'\ttype: '%T'\tcomp: %v\n", sectionName, sectionName, key, key, sectionName == key)
        }
    }
}

// printHeaders Function simply prints imports in a nice way, i should make one that generate a csv output to be simpler to parse out
// need to parse header data to recognise packers and so on
func printHeaders(pe *peparser.File) {

	fmt.Printf("HEADERS:\n\n")

	if pe.FileInfo.HasDOSHdr {
		fmt.Printf("\tDOS Header:\n%v\n\n", pe.DOSHeader)
	} else {
		fmt.Printf("\tDOS Header:\tDOS Header is empty !\n\n")
	}
	if pe.FileInfo.HasRichHdr {
		fmt.Printf("\tRich Header:\n%v\n\n", pe.RichHeader)
	} else {
		fmt.Printf("\tRich Header:\tRich Header is empty !\n\n")
	}
	if pe.FileInfo.HasNTHdr {
		fmt.Printf("\tNT Header:\n%v\n\n", pe.NtHeader)
	} else {
		fmt.Printf("\tNT Header:\tNT Header is empty !\n\n")
	}
}

// printCOFF Function simply prints imports in a nice way, i should make one that generate a csv output to be simpler to parse out
func printCOFF(pe *peparser.File) {
	if pe.FileInfo.HasCOFF {
		fmt.Printf("COFF:\n\n")
		// maybe implement this to be pretty printed
		fmt.Printf("\t%v\n\n", pe.COFF)
	} else {
		fmt.Printf("COFF:\tsymbol table is empty !\n\n")
	}
}

// printSections Function simply prints imports in a nice way, i should make one that generate a csv output to be simpler to parse out
func printSections(pe *peparser.File) {
	if pe.FileInfo.HasSections {
		fmt.Printf("SECTIONS:\n")
		for _, sec := range pe.Sections {
			//flags := sec.PrettySectionFlags()
			checkSectionsStandard(fmt.Sprintf("%s", sec.Header.Name))//, flags)

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

		//checkSections(peFile)

		/*
		   printHeaders(peFile)

		   printCOFF(peFile)

		   printSections(peFile)

		   impMap, err := getFunctions(peFile)
		   if err != nil {
		       fmt.Printf("%s", err)
		   } else {
		       printImports(impMap)
		   }
		*/
	}
	fmt.Println()
}
