package main

import (
    "encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

    //yara "github.com/hillu/go-yara/v4"
	peparser "github.com/saferwall/pe"
)

const (
	ENTROPY = iota
	SECTIONS
	HEADERS
	COFF
	IMPORTS
	ANOMALIES
	DOS
	RICH
	NT
    CERTIFICATES
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

const ARGNUMBER = 10
var arguments = [ARGNUMBER]*bool{}
var entropy bool = false

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

// parserFile Function, as it's named parse a PE file and retrieve the pe.File structure that contains all the informations
func parseFile(filePath string) *peparser.File {

	pe, err := peparser.New(filePath, &peparser.Options{})
	if err != nil {
		panic(fmt.Sprintf("Error while opening file: %s, reason: %v", filePath, err))
	}

	pe.Parse()
	return pe
}

// printAnomalies Function prints anomalies detected by the library if any
func printAnomalies(pe *peparser.File, isOption bool) {
	if len(pe.Anomalies) > 0 {
		fmt.Printf("ANOMALIES FOUND:\n\n")
		for _, an := range pe.Anomalies {
			fmt.Printf("\t%s\n", an)
		}
	} else {
		if isOption {
			fmt.Printf("Nothing anormal was found in the file.\n")
		}
	}
}

// checkSectionsStandard Function verifies if the sections of the PE file are "standard" using the Microsoft standard from: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format It then prints the output if anything was not standard
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
	// add the different printouts
	printDOSHeader(pe, false)
	printNTHeader(pe, false)
	printRichHeader(pe, false)
}

func printDOSHeader(pe *peparser.File, isOption bool) {
	if isOption {
		fmt.Printf("DOS Header:\n\n")
	}
	if pe.FileInfo.HasDOSHdr {
		fmt.Printf("\tDOS Header:\n\t\t%v\n\n", pe.DOSHeader)
	} else {
		fmt.Printf("\tDOS Header:\n\t\tDOS Header is empty !\n\n")
	}
}

func printNTHeader(pe *peparser.File, isOption bool) {
	if isOption {
		fmt.Printf("NT Header:\n\n")
	}
	if pe.FileInfo.HasNTHdr {
		fmt.Printf("\tNT Header:\n\t\t%v\n\n", pe.NtHeader)
	} else {
		fmt.Printf("\tNT Header:\n\t\tNT Header is empty !\n\n")
	}
}

func printRichHeader(pe *peparser.File, isOption bool) {
	if isOption {
		fmt.Printf("Rich Header:\n\n")
	}
	if pe.FileInfo.HasRichHdr {
		fmt.Printf("\tRich Header:\n\t\t%v\n\n", pe.RichHeader)
	} else {
		fmt.Printf("\tRich Header:\n\t\tRich Header is empty !\n\n")
	}
}

// printCOFF Function prints the COFF
func printCOFF(pe *peparser.File, isOption bool) {
	if isOption {
		fmt.Printf("COFF Header:\n\n")
	}
	if pe.FileInfo.HasCOFF {
		fmt.Printf("COFF:\n\n")
		// maybe implement this to be pretty printed
		fmt.Printf("\t%v\n\n", pe.COFF)
	} else {
		fmt.Printf("COFF:\n\tsymbol table is empty !\n\n")
	}
}

// printSections Function simply prints sections in a nice way
func printSections(pe *peparser.File, entropy bool) {
	if pe.FileInfo.HasSections {
		fmt.Printf("SECTIONS:\n\n")
		for _, sec := range pe.Sections {

			ent := sec.CalculateEntropy(pe)
			flags := sec.PrettySectionFlags()

			fmt.Printf(
				"\t%s\n",
				strings.TrimRight(
					fmt.Sprintf("%s", sec.Header.Name),
					"\x00"))
            if entropy {
			    fmt.Printf("\t\tEntropy:\t%f\n", ent)
            }
			s := strings.TrimRight(fmt.Sprintf("%s", sec.Header.Name), "\x00")

			checkSectionsStandard(s, flags)

		}
		fmt.Println()
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

func printCertificates(pe *peparser.File) {
    fmt.Printf("CERTIFICATES:\n")
    if len(pe.Certificates.Certificates) == 0 {
        fmt.Printf("\tNo certificate found !\n")
    } else {
        certs := pe.Certificates.Certificates
        for _, crt := range certs {
            fmt.Printf("\n\tInformations:\n\t\tCertificate Authority:\t%s\n\t\tOwner:\t%s\n\t\tValidity:\t%s to %s\n\t\tSerial Number:\t%s\n\t\tPublic Key Algorithm:\t%s\n\t\tCertificate Authority Algorithm:\t%s",
                crt.Info.Issuer,
                crt.Info.Subject,
                crt.Info.NotBefore,
                crt.Info.NotAfter,
                crt.Info.SerialNumber,
                crt.Info.PublicKeyAlgorithm,
                crt.Info.SignatureAlgorithm,
            )
            fmt.Printf("\n\tSignature Validation:\t%v\n\tSigner Verified:\t%v", 
                crt.SignatureValid,
                crt.Verified,
            )
            fmt.Printf("\n\tContent Signature (%s):\t%s\n",
                crt.SignatureContent.Algorithm,
                hex.EncodeToString(crt.SignatureContent.HashResult),
            )
        }
    }
    fmt.Println()
}

func abort(err error) {
	fmt.Println(err)
	flag.PrintDefaults()
	os.Exit(1)
}

func isDefaultArguments() bool {
	for _, arg := range arguments {
		if *arg {
			return false
		}
	}
	return true
}

func runParam(peFile *peparser.File, par int, isOption bool) {
	switch par {
	case ENTROPY:
        entropy = true
	case SECTIONS:
		printSections(peFile, entropy)
	case HEADERS:
		printHeaders(peFile)
	case COFF:
		printCOFF(peFile, isOption)
	case IMPORTS:
		fn, err := getFunctions(peFile)
		if err != nil {
			fmt.Printf("%s", err)
		}
		printImports(fn)
	case ANOMALIES:
		printAnomalies(peFile, isOption)
	case DOS:
		printDOSHeader(peFile, isOption)
	case RICH:
		printRichHeader(peFile, isOption)
	case NT:
		printNTHeader(peFile, isOption)
    case CERTIFICATES:
        printCertificates(peFile)
	default:
		panic(fmt.Errorf("Can't handle parameter, got '%d'", par))
	}
}

func runDefault(peFile *peparser.File) {
	for index := range arguments {
		switch index {
		case COFF, NT, RICH, DOS:
			continue
		default:
			runParam(peFile, index, false)
		}
	}
}

func runCustom(peFile *peparser.File) {
	for i, v := range arguments {
			if *v == true {
				runParam(peFile, i, true)
			}
	}
}

func main() {

	arguments = [ARGNUMBER]*bool{
		flag.Bool("entropy", false, "Calculates the entropy levels."),
		flag.Bool("sections", false, "Print sections from the PE file."),
		flag.Bool("headers", false, "Print all headers from the PE file."),
		flag.Bool("coff", false, "Print coff of the PE file."),
		flag.Bool("imports", false, "Print imports from the PE file."),
		flag.Bool("anomalies", false, "Print anomalies encountered when parsing the PE file if any."),
		flag.Bool("dos", false, "Print the DOS header of the PE file."),
		flag.Bool("rich", false, "Print the Rich header of the PE file."),
		flag.Bool("nt", false, "Print the NT header of the PE file."),
        flag.Bool("certificates", false, "Print the certificates of the PE file."),
	}

	flag.Parse()

	files := make([]string, 0)

	if len(os.Args) > 1 {
		for _, arg := range os.Args[1:] {
			if _, err := os.Stat(arg); err != nil {
				continue
			} else {
				files = append(files, arg)
			}
		}

		for _, f := range files {

			peFile := parseFile(f)

			fmt.Printf("\nFILE:\t%s\n\n", f)

			if isDefaultArguments() {
				runDefault(peFile)
			} else {
				runCustom(peFile)
			}
		}
	} else {
		fmt.Printf("\nNot enough parameters.\n\nUsage: ./pexp [ARGUMENTS...] [FILE-PATH]\n\nAvailable arguments:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
}
