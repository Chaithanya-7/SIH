; Registers the phishlens:// scheme from the installer itself.
;
; The application also claims the scheme at startup, and that works on every
; ordinary launch - measured repeatedly at about one second, including when
; another executable already holds it. What it does not survive is the one
; launch the installer performs itself: after a fresh install the scheme was
; still unregistered, while running the very same installed binary by hand
; registered it immediately. Every mechanism the installer uses was reproduced
; by hand - ShellExecute, a .lnk shortcut, the --updated argument - and all of
; them registered normally, so the cause lies in the installer's process
; context rather than in how the app is invoked. The installer's manifest
; requests asInvoker, so it is not an elevation mismatch either.
;
; Chasing that further would be the wrong way round. The scheme belongs to the
; installation, so the installer is where it should be written: it runs once,
; at a known moment, with the install path already resolved.
;
; This also fixes a leftover the uninstaller left behind. The app wrote the key
; at runtime, so NSIS had nothing to remove and the scheme kept pointing at a
; deleted executable after uninstalling. Now that the installer owns the key,
; the uninstaller can take it away again.

!macro customInstall
  DetailPrint "Registering the phishlens:// protocol handler..."

  WriteRegStr HKCU "Software\Classes\phishlens" "" "URL:PhishLens Protocol"
  WriteRegStr HKCU "Software\Classes\phishlens" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\phishlens\DefaultIcon" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME},0"
  WriteRegStr HKCU "Software\Classes\phishlens\shell\open\command" "" '"$INSTDIR\${APP_EXECUTABLE_FILENAME}" "%1"'

  ; Reads back what actually landed and records it beside the application.
  ;
  ; Written because "did this macro run, and did its write take effect" could
  ; not be answered from outside: the NSIS script is compressed into the
  ; installer, and the registry afterwards only shows an end state without
  ; saying who produced it. A file the macro writes itself answers both at once.
  ClearErrors
  ReadRegStr $R0 HKCU "Software\Classes\phishlens\shell\open\command" ""
  StrCpy $R2 "ok"
  ${If} ${Errors}
    StrCpy $R2 "read-back failed"
  ${EndIf}

  FileOpen $R1 "$INSTDIR\protocol-registration.log" w
  FileWrite $R1 "customInstall ran$\r$\n"
  FileWrite $R1 "INSTDIR=$INSTDIR$\r$\n"
  FileWrite $R1 "handler after write=$R0$\r$\n"
  FileWrite $R1 "read-back=$R2$\r$\n"
  FileClose $R1
!macroend

!macro customUnInstall
  ; Only removed on a real uninstall, not the removal step of an upgrade -
  ; otherwise an update would tear down the handler it is about to rewrite.
  ${ifNot} ${isUpdated}
    DetailPrint "Removing the phishlens:// protocol handler..."
    DeleteRegKey HKCU "Software\Classes\phishlens"
  ${endif}
!macroend
