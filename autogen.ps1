# Script to generate the necessary files for a msvscpp build
#
# Version: 20260607

$WinFlex = "..\win_flex_bison\win_flex.exe"
$WinBison = "..\win_flex_bison\win_bison.exe"

$Project = Get-Content -Path configure.ac | select -skip 3 -first 1 | % { $_ -Replace "  \[","" } | % { $_ -Replace "\],","" }
$Version = Get-Content -Path configure.ac | select -skip 4 -first 1 | % { $_ -Replace "  \[","" } | % { $_ -Replace "\],","" }
$Prefix = ${Project}.Substring(3)

Get-Content -Path "common\types.h.in" | % { $_ -Replace "@PACKAGE@","${Project}" } | Out-File -Encoding ascii "common\types.h"

If (Test-Path "include\${Project}.h.in")
{
	Get-Content -Path "include\${Project}.h.in" | Out-File -Encoding ascii "include\${Project}.h"
	Get-Content -Path "include\${Project}\definitions.h.in" | % { $_ -Replace "@VERSION@","${Version}" } | Out-File -Encoding ascii "include\${Project}\definitions.h"
	Get-Content -Path "include\${Project}\features.h.in" | % { $_ -Replace "@[A-Z0-9_]*@","0" } | Out-File -Encoding ascii "include\${Project}\features.h"
	Get-Content -Path "include\${Project}\types.h.in" | % { $_ -Replace "@[A-Z0-9_]*@","0" } | Out-File -Encoding ascii "include\${Project}\types.h"
}
If (Test-Path "${Project}\${Project}.c")
{
	Get-Content -Path "${Project}\${Project}_definitions.h.in" | % { $_ -Replace "@VERSION@","${Version}" } | Out-File -Encoding ascii "${Project}\${Project}_definitions.h"
	Get-Content -Path "${Project}\${Project}.rc.in" | % { $_ -Replace "@VERSION@","${Version}" } | Out-File -Encoding ascii "${Project}\${Project}.rc"
}
If (Test-Path "pyproject.toml.in")
{
	Get-Content -Path "pyproject.toml.in" | % { $_ -Replace "@VERSION@","${Version}" } | Out-File -Encoding ascii "pyproject.toml"
}
If (Test-Path "${Prefix}.net")
{
	Get-Content -Path "${Prefix}.net\${Prefix}.net.rc.in" | % { $_ -Replace "@VERSION@","${Version}" } | Out-File -Encoding ascii "${Prefix}.net\${Prefix}.net.rc"
}

$NamePrefix = ""

ForEach (${Project} in Get-ChildItem -Directory -Path "lib*")
{
	ForEach (${DirectoryElement} in Get-ChildItem -Path "${Project}\*.l")
	{
		$OutputFile = ${DirectoryElement} -Replace ".l$",".c"

		$NamePrefix = Split-Path -path ${DirectoryElement} -leaf
		$NamePrefix = ${NamePrefix} -Replace ".l$","_"

		Write-Host "Running: ${WinFlex} -Cf ${DirectoryElement}"

		# PowerShell will raise NativeCommandError if win_flex writes to stdout or stderr
		# therefore 2>&1 is added and the output is stored in a variable.
		$Output = Invoke-Expression -Command "& '${WinFlex}' -Cf ${DirectoryElement} 2>&1"
		Write-Host ${Output}

		# Moving manually since `win_flex -o filename' does not provide the expected behavior.
		Move-Item "lex.yy.c" ${OutputFile} -force
	}

	ForEach (${DirectoryElement} in Get-ChildItem -Path "${Project}\*.y")
	{
		$OutputFile = ${DirectoryElement} -Replace ".y$",".c"

		Write-Host "Running: ${WinBison} -d -v -l -p ${NamePrefix} -o ${OutputFile} ${DirectoryElement}"

		# PowerShell will raise NativeCommandError if win_bison writes to stdout or stderr
		# therefore 2>&1 is added and the output is stored in a variable.
		$Output = Invoke-Expression -Command "& '${WinBison}' -d -v -l -p ${NamePrefix} -o ${OutputFile} ${DirectoryElement} 2>&1"
		Write-Host ${Output}
	}
}

