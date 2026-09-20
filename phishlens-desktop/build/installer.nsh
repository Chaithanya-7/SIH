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
; context rather than in how the app is invoked.
;
; Chasing that further would be the wrong way round. The scheme belongs to the
; installation, so the installer is where it should be written: it runs once,
; at a known moment, with the install path already resolved.
;
; This also fixes a leftover the uninstaller previously left behind. The app
; wrote the key at runtime, so NSIS had nothing to remove and the scheme kept
; pointing at a deleted executable after uninstalling. Now that the installer
; owns the key, the uninstaller can take it away again.

!macro customInstall
  DetailPrint "Registering the phishlens:// protocol handler..."
  WriteRegStr HKCU "Software\Classes\phishlens" "" "URL:PhishLens Protocol"
  WriteRegStr HKCU "Software\Classes\phishlens" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\phishlens\DefaultIcon" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME},0"
  WriteRegStr HKCU "Software\Classes\phishlens\shell\open\command" "" '"$INSTDIR\${APP_EXECUTABLE_FILENAME}" "%1"'
!macroend

!macro customUnInstall
  ; Only removed when this is a real uninstall rather than the removal step of
  ; an upgrade - otherwise an update would tear down the handler it is about to
  ; write again.
  ${ifNot} ${isUpdated}
    DetailPrint "Removing the phishlens:// protocol handler..."
    DeleteRegKey HKCU "Software\Classes\phishlens"
  ${endif}
!macroend
