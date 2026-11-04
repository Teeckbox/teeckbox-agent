; The installer of the Teeckbox agent for Windows (NSIS, zlib licence: free for commercial use): a wizard that asks for the
; address of Teeckbox, the one-time enrollment code and the allow list, installs the program, registers the service under its
; own virtual account, enrols the agent and starts it. Built by the release workflow:
;
;   makensis /DVERSION=0.1.0 /DVERSIONNUM=0.1.0.0 /DSOURCEDIR=out deploy\windows\installer.nsi
;
; Silent installation (deployment tools): setup.exe /S /URL=https://teeckbox.example.com /CODE=tbe_... /ALLOW=erp.corp.example.com:443,10.20.0.0/16
; (optional: /PROXY=http://proxy:3128 /LABEL=name). Running it again on a machine that is enrolled upgrades the program and
; keeps the keys.

Unicode true
RequestExecutionLevel admin

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef VERSIONNUM
  !define VERSIONNUM "0.0.0.0"
!endif
!ifndef SOURCEDIR
  !define SOURCEDIR "..\..\out"
!endif

!define SERVICE "TeeckboxAgent"
!define ACCOUNT "NT SERVICE\${SERVICE}"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\TeeckboxAgent"

Name "Teeckbox agent"
OutFile "..\..\dist\teeckbox-agent-${VERSION}-win-x64-setup.exe"
InstallDir "$PROGRAMFILES64\Teeckbox Agent"
BrandingText "Teeckbox agent ${VERSION}"
VIProductVersion "${VERSIONNUM}"
VIAddVersionKey "ProductName" "Teeckbox agent"
VIAddVersionKey "CompanyName" "Teeckbox"
VIAddVersionKey "LegalCopyright" "Apache-2.0"
VIAddVersionKey "FileDescription" "Teeckbox agent installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "StrFunc.nsh"
!include "x64.nsh"

${StrStr}
${StrRep}

Var Url
Var Code
Var Proxy
Var Allow
Var Label
Var Enrolled
Var UrlEdit
Var CodeEdit
Var ProxyEdit
Var AllowEdit

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
Page custom ConnectionPage ConnectionLeave
Page custom AllowPage AllowLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP|MB_OK "The Teeckbox agent needs a 64-bit Windows." /SD IDOK
    Abort
  ${EndIf}
  SetRegView 64
  ${DisableX64FSRedirection}
  SetShellVarContext all

  ${GetParameters} $R0
  ${GetOptions} $R0 "/URL=" $Url
  ${GetOptions} $R0 "/CODE=" $Code
  ${GetOptions} $R0 "/PROXY=" $Proxy
  ${GetOptions} $R0 "/ALLOW=" $Allow
  ${GetOptions} $R0 "/LABEL=" $Label

  StrCpy $Enrolled 0
  ${If} ${FileExists} "$APPDATA\Teeckbox\Agent\data\state.json"
    StrCpy $Enrolled 1
  ${EndIf}
FunctionEnd

; ---- The pages: skipped when the agent is enrolled already (an upgrade has nothing to ask) ----

Function ConnectionPage
  ${If} $Enrolled == 1
    Abort
  ${EndIf}
  !insertmacro MUI_HEADER_TEXT "Connection to Teeckbox" "In Teeckbox, open Connections > Agents > New agent: it shows the address and a one-time code, valid 15 minutes."
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 10u "Address of Teeckbox (https://...):"
  Pop $0
  ${NSD_CreateText} 0 12u 100% 12u "$Url"
  Pop $UrlEdit
  ${NSD_CreateLabel} 0 34u 100% 10u "Enrollment code (tbe_...):"
  Pop $0
  ${NSD_CreateText} 0 46u 100% 12u "$Code"
  Pop $CodeEdit
  ${NSD_CreateLabel} 0 68u 100% 10u "HTTP proxy to reach Teeckbox (leave empty if none):"
  Pop $0
  ${NSD_CreateText} 0 80u 100% 12u "$Proxy"
  Pop $ProxyEdit
  nsDialogs::Show
FunctionEnd

Function ConnectionLeave
  ${NSD_GetText} $UrlEdit $Url
  ${NSD_GetText} $CodeEdit $Code
  ${NSD_GetText} $ProxyEdit $Proxy

  StrCpy $0 $Url 8
  StrCpy $1 $Url 16
  ${If} $0 != "https://"
  ${AndIf} $1 != "http://localhost"
  ${AndIf} $1 != "http://127.0.0.1"
    MessageBox MB_ICONEXCLAMATION|MB_OK "The address of Teeckbox must start with https:// (for example https://teeckbox.example.com)."
    Abort
  ${EndIf}
  StrCpy $0 $Code 4
  ${If} $0 != "tbe_"
    MessageBox MB_ICONEXCLAMATION|MB_OK "The enrollment code starts with tbe_. Create one in Teeckbox: Connections > Agents > New agent."
    Abort
  ${EndIf}
  ${If} $Proxy != ""
    StrCpy $0 $Proxy 4
    ${If} $0 != "http"
      MessageBox MB_ICONEXCLAMATION|MB_OK "The proxy is an address such as http://proxy.example.com:3128, or empty."
      Abort
    ${EndIf}
  ${EndIf}
  ${StrStr} $0 "$Url$Code$Proxy" '"'
  ${If} $0 != ""
    MessageBox MB_ICONEXCLAMATION|MB_OK "A quotation mark is not allowed here."
    Abort
  ${EndIf}
FunctionEnd

Function AllowPage
  ${If} $Enrolled == 1
    Abort
  ${EndIf}
  !insertmacro MUI_HEADER_TEXT "What the agent may call" "The systems of your network that Teeckbox may reach through this agent. Anything not listed is refused."
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 36u "One destination per line: a host name (erp.corp.example.com, or *.corp.example.com for any name below it) or an address or range (10.20.0.0/16), optionally followed by :port (erp.corp.example.com:443). The list is kept in agent.yaml, which you can edit later."
  Pop $0
  ${StrRep} $1 "$Allow" "," "$\r$\n"
  nsDialogs::CreateControl ${__NSD_Text_CLASS} ${DEFAULT_STYLES}|${WS_TABSTOP}|${WS_VSCROLL}|${ES_MULTILINE}|${ES_WANTRETURN}|${ES_AUTOVSCROLL} ${__NSD_Text_EXSTYLE} 0 40u 100% 90u "$1"
  Pop $AllowEdit
  nsDialogs::Show
FunctionEnd

Function AllowLeave
  ${NSD_GetText} $AllowEdit $Allow
  ${StrRep} $Allow "$Allow" "$\r$\n" ","
  ${StrStr} $0 "$Allow" '"'
  ${If} $0 != ""
    MessageBox MB_ICONEXCLAMATION|MB_OK "A quotation mark is not allowed here."
    Abort
  ${EndIf}
  ${If} $Allow == ""
    MessageBox MB_ICONQUESTION|MB_YESNO "The list is empty: the agent will refuse every call until you list destinations in agent.yaml. Continue anyway?" IDYES +2
    Abort
  ${EndIf}
FunctionEnd

; ---- The installation ----

; $0 = what to tell the person. Undoes what was done, so that nothing half-installed is left behind.
Function FailInstall
  nsExec::Exec '"$SYSDIR\sc.exe" delete ${SERVICE}'
  Delete "$INSTDIR\teeckbox-agent.exe"
  Delete "$INSTDIR\install-service.ps1"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  MessageBox MB_ICONSTOP|MB_OK "$0" /SD IDOK
  SetErrorLevel 2
  Abort
FunctionEnd

Section "Install"
  SetShellVarContext all
  StrCpy $R1 "$APPDATA\Teeckbox\Agent"

  ${If} $Enrolled == 0
  ${AndIf} $Url == ""
    StrCpy $0 "The address of Teeckbox and the enrollment code are needed: /URL=... /CODE=..."
    MessageBox MB_ICONSTOP|MB_OK "$0" /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}
  ${If} $Enrolled == 0
  ${AndIf} $Code == ""
    MessageBox MB_ICONSTOP|MB_OK "The address of Teeckbox and the enrollment code are needed: /URL=... /CODE=..." /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}

  ; An upgrade: the program cannot be replaced while it runs.
  nsExec::Exec '"$SYSDIR\sc.exe" query ${SERVICE}'
  Pop $R2   ; 0 when the service exists already
  ${If} $R2 == 0
    nsExec::Exec '"$SYSDIR\sc.exe" stop ${SERVICE}'
    Pop $0
    Sleep 3000
  ${EndIf}

  SetOutPath "$INSTDIR"
  File "${SOURCEDIR}\teeckbox-agent.exe"
  File "install-service.ps1"
  File "..\..\LICENSE"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "Teeckbox agent"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "Teeckbox"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "URLInfoAbout" "https://teeckbox.com"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\teeckbox-agent.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1

  ${If} $R2 != 0
    ; First installation: the service, under its own virtual account.
    nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\install-service.ps1" -ExePath "$INSTDIR\teeckbox-agent.exe" -ConfigPath "$R1\agent.yaml"'
    Pop $0
    ${If} $0 != 0
      StrCpy $0 "The Windows service could not be installed."
      Call FailInstall
    ${EndIf}
  ${EndIf}
  ; The service reads the program and the configuration; it writes only its data folder.
  nsExec::Exec '"$SYSDIR\icacls.exe" "$INSTDIR" /grant "${ACCOUNT}:(OI)(CI)RX"'
  Pop $0

  ${If} $Enrolled == 0
    StrCpy $2 '"$INSTDIR\teeckbox-agent.exe" enroll --url "$Url" --code "$Code" --config "$R1\agent.yaml" --data-folder "$R1\data" --grant "${ACCOUNT}"'
    ${If} $Proxy != ""
      StrCpy $2 '$2 --proxy "$Proxy"'
    ${EndIf}
    ${If} $Allow != ""
      StrCpy $2 '$2 --allow "$Allow"'
    ${EndIf}
    ${If} $Label != ""
      StrCpy $2 '$2 --label "$Label"'
    ${EndIf}
    DetailPrint "Enrolling the agent with Teeckbox"
    nsExec::ExecToStack '$2'
    Pop $0
    Pop $1
    ${If} $0 != 0
      StrCpy $0 "The agent could not be enrolled:$\r$\n$\r$\n$1$\r$\nThe installation was cancelled. The code can be used once: create a new one in Teeckbox and run this installer again."
      Call FailInstall
    ${EndIf}
    DetailPrint "$1"
  ${EndIf}

  nsExec::Exec '"$SYSDIR\sc.exe" start ${SERVICE}'
  Pop $0
  Sleep 2500
  nsExec::Exec '"$SYSDIR\cmd.exe" /C ""$SYSDIR\sc.exe" query ${SERVICE} | "$SYSDIR\findstr.exe" RUNNING"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "The agent is installed but the service is not running. See the Windows Event Viewer (Windows Logs > Application), then start it with: Start-Service ${SERVICE}" /SD IDOK
  ${EndIf}
SectionEnd

; ---- The removal ----

Function un.onInit
  SetRegView 64
  ${DisableX64FSRedirection}
  SetShellVarContext all
FunctionEnd

Section "Uninstall"
  nsExec::Exec '"$SYSDIR\sc.exe" stop ${SERVICE}'
  Pop $0
  Sleep 2000
  nsExec::Exec '"$SYSDIR\sc.exe" delete ${SERVICE}'
  Pop $0
  Delete "$INSTDIR\teeckbox-agent.exe"
  Delete "$INSTDIR\install-service.ps1"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"

  ${If} ${FileExists} "$APPDATA\Teeckbox\Agent\*.*"
    MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Also delete the keys and the configuration of the agent ($APPDATA\Teeckbox\Agent)?$\r$\n$\r$\nKeep them to install the agent again without enrolling it again. Disable the instance in Teeckbox (Connections > Agents) if you remove it for good." /SD IDNO IDNO keep
    RMDir /r "$APPDATA\Teeckbox\Agent"
    RMDir "$APPDATA\Teeckbox"
    keep:
  ${EndIf}
SectionEnd
