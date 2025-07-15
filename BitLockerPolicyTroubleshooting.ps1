# Aynı OU'daki bilgisayarlar arasında BitLocker politika farklılıklarını analiz eden script

function Test-BitLockerPolicyDifferences {
    param(
        [string]$OUPath,
        [string[]]$ComputerNames = @(),
        [string]$OutputPath = $null
    )
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop
        
        Write-Host "BitLocker politika farklılıkları analiz ediliyor..." -ForegroundColor Yellow
        
        # OU'daki bilgisayarları al
        if ($ComputerNames.Count -eq 0) {
            if ($OUPath) {
                $computers = Get-ADComputer -SearchBase $OUPath -Filter * -Properties Name, OperatingSystem, LastLogonDate, whenCreated, Enabled
            } else {
                Write-Error "OU Path veya Computer Names belirtilmeli"
                return
            }
        } else {
            $computers = $ComputerNames | ForEach-Object { Get-ADComputer -Identity $_ -Properties Name, OperatingSystem, LastLogonDate, whenCreated, Enabled }
        }
        
        $analysisResults = @()
        
        foreach ($computer in $computers) {
            Write-Progress -Activity "Bilgisayarlar analiz ediliyor" -Status "İşleniyor: $($computer.Name)" -PercentComplete (($computers.IndexOf($computer) / $computers.Count) * 100)
            
            $computerAnalysis = [PSCustomObject]@{
                ComputerName = $computer.Name
                OperatingSystem = $computer.OperatingSystem
                LastLogonDate = $computer.LastLogonDate
                AccountEnabled = $computer.Enabled
                CreatedDate = $computer.whenCreated
                Online = $false
                PolicyIssues = @()
                GPOApplicationStatus = @()
                BitLockerSupported = $false
                TPMStatus = "Unknown"
                SecurityGroups = @()
                BlockedInheritance = $false
                WMIFilters = @()
                PolicyProcessingErrors = @()
                NetworkConnectivity = "Unknown"
                DomainJoinStatus = "Unknown"
                LastGroupPolicyRefresh = "Unknown"
                BitLockerStatus = "Unknown"
                RecommendedActions = @()
            }
            
            # 1. Bilgisayarın çevrimiçi durumunu kontrol et
            if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet) {
                $computerAnalysis.Online = $true
                $computerAnalysis.NetworkConnectivity = "Online"
                
                try {
                    # Remote bilgisayarda analiz yap
                    $remoteAnalysis = Invoke-Command -ComputerName $computer.Name -ScriptBlock {
                        $result = @{}
                        
                        # BitLocker desteğini kontrol et
                        try {
                            $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
                            $result.BitLockerSupported = $bitlockerVolumes -ne $null
                            $result.BitLockerStatus = if ($bitlockerVolumes) { 
                                ($bitlockerVolumes | Where-Object { $_.VolumeType -eq "OperatingSystem" }).VolumeStatus 
                            } else { "Not Supported" }
                        } catch {
                            $result.BitLockerSupported = $false
                            $result.BitLockerStatus = "Error: $($_.Exception.Message)"
                        }
                        
                        # TPM durumunu kontrol et
                        try {
                            $tpm = Get-Tpm -ErrorAction SilentlyContinue
                            $result.TPMStatus = if ($tpm) { 
                                "Present: $($tpm.TpmPresent), Enabled: $($tpm.TpmEnabled), Activated: $($tpm.TpmActivated)"
                            } else { "Not Available" }
                        } catch {
                            $result.TPMStatus = "Error checking TPM"
                        }
                        
                        # Group Policy son yenileme zamanını al
                        try {
                            $gpRefresh = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine" -Name "LastGPORefreshTime" -ErrorAction SilentlyContinue
                            $result.LastGroupPolicyRefresh = if ($gpRefresh) { $gpRefresh.LastGPORefreshTime } else { "Unknown" }
                        } catch {
                            $result.LastGroupPolicyRefresh = "Error reading registry"
                        }
                        
                        # Domain join durumunu kontrol et
                        try {
                            $computerInfo = Get-ComputerInfo -Property CsDomain, CsDomainRole -ErrorAction SilentlyContinue
                            $result.DomainJoinStatus = "$($computerInfo.CsDomain) - Role: $($computerInfo.CsDomainRole)"
                        } catch {
                            $result.DomainJoinStatus = "Error getting domain info"
                        }
                        
                        # GP uygulama loglarını kontrol et
                        try {
                            $gpEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=1502,1503,1500,1501; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 10 -ErrorAction SilentlyContinue
                            $result.PolicyProcessingErrors = $gpEvents | Where-Object { $_.LevelDisplayName -eq "Error" } | ForEach-Object { $_.Message }
                        } catch {
                            $result.PolicyProcessingErrors = @("Could not read event logs")
                        }
                        
                        # BitLocker politika registry anahtarlarını kontrol et
                        $bitlockerRegKeys = @()
                        $regPaths = @(
                            "HKLM:\SOFTWARE\Policies\Microsoft\FVE",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FVE"
                        )
                        
                        foreach ($regPath in $regPaths) {
                            if (Test-Path $regPath) {
                                $keys = Get-ChildItem $regPath -Recurse -ErrorAction SilentlyContinue
                                $bitlockerRegKeys += $keys | ForEach-Object { "$regPath\$($_.Name)" }
                            }
                        }
                        $result.BitLockerRegistryKeys = $bitlockerRegKeys
                        
                        return $result
                    } -ErrorAction SilentlyContinue
                    
                    if ($remoteAnalysis) {
                        $computerAnalysis.BitLockerSupported = $remoteAnalysis.BitLockerSupported
                        $computerAnalysis.TPMStatus = $remoteAnalysis.TPMStatus
                        $computerAnalysis.LastGroupPolicyRefresh = $remoteAnalysis.LastGroupPolicyRefresh
                        $computerAnalysis.DomainJoinStatus = $remoteAnalysis.DomainJoinStatus
                        $computerAnalysis.PolicyProcessingErrors = $remoteAnalysis.PolicyProcessingErrors
                        $computerAnalysis.BitLockerStatus = $remoteAnalysis.BitLockerStatus
                    }
                } catch {
                    $computerAnalysis.PolicyIssues += "Remote connection failed: $($_.Exception.Message)"
                }
            } else {
                $computerAnalysis.NetworkConnectivity = "Offline"
                $computerAnalysis.PolicyIssues += "Computer is offline"
            }
            
            # 2. Security Group üyeliklerini kontrol et
            try {
                $groups = Get-ADPrincipalGroupMembership -Identity $computer.Name -ErrorAction SilentlyContinue
                $computerAnalysis.SecurityGroups = $groups | ForEach-Object { $_.Name }
            } catch {
                $computerAnalysis.PolicyIssues += "Could not read security groups"
            }
            
            # 3. GPO uygulama durumunu kontrol et
            try {
                $gpoStatus = Get-GPResultantSetOfPolicy -Computer $computer.Name -ReportType Xml -ErrorAction SilentlyContinue
                if ($gpoStatus) {
                    # XML'i parse et ve BitLocker politikalarını ara
                    if ($gpoStatus -match "BitLocker|FVE") {
                        $computerAnalysis.GPOApplicationStatus += "BitLocker policies found in RSoP"
                    } else {
                        $computerAnalysis.GPOApplicationStatus += "No BitLocker policies in RSoP"
                        $computerAnalysis.PolicyIssues += "BitLocker policies not applied via Group Policy"
                    }
                } else {
                    $computerAnalysis.PolicyIssues += "Could not generate RSoP report"
                }
            } catch {
                $computerAnalysis.PolicyIssues += "RSoP generation failed: $($_.Exception.Message)"
            }
            
            # 4. WMI Filter kontrolü
            try {
                $appliedGPOs = Get-ADObject -Filter "gPLink -like '*'" -Properties gPLink | Where-Object { $_.gPLink -match "BitLocker" }
                foreach ($gpo in $appliedGPOs) {
                    $gpoDetails = Get-GPO -Name $gpo.Name -ErrorAction SilentlyContinue
                    if ($gpoDetails.WmiFilter) {
                        $computerAnalysis.WMIFilters += "GPO: $($gpoDetails.DisplayName) has WMI Filter: $($gpoDetails.WmiFilter.Name)"
                    }
                }
            } catch {
                $computerAnalysis.PolicyIssues += "WMI Filter check failed"
            }
            
            # 5. Inheritance blocking kontrolü
            try {
                $inheritance = Get-GPInheritance -Target $computer.DistinguishedName -ErrorAction SilentlyContinue
                if ($inheritance.GpoInheritanceBlocked) {
                    $computerAnalysis.BlockedInheritance = $true
                    $computerAnalysis.PolicyIssues += "Group Policy inheritance is blocked"
                }
            } catch {
                $computerAnalysis.PolicyIssues += "Inheritance check failed"
            }
            
            # 6. Önerilen aksiyonları belirle
            $computerAnalysis.RecommendedActions = Get-RecommendedActions -Analysis $computerAnalysis
            
            $analysisResults += $computerAnalysis
        }
        
        Write-Progress -Activity "Bilgisayarlar analiz ediliyor" -Completed
        
        # Sonuçları göster
        Show-AnalysisResults -Results $analysisResults
        
        # CSV'ye kaydet
        if ($OutputPath) {
            Export-AnalysisResults -Results $analysisResults -OutputPath $OutputPath
        }
        
        return $analysisResults
    }
    catch {
        Write-Error "Analysis failed: $($_.Exception.Message)"
    }
}

function Get-RecommendedActions {
    param($Analysis)
    
    $actions = @()
    
    # Çevrimdışı bilgisayar
    if (-not $Analysis.Online) {
        $actions += "Bilgisayarın çevrimiçi olduğundan emin olun"
        $actions += "Ağ bağlantısını kontrol edin"
    }
    
    # BitLocker desteği yok
    if (-not $Analysis.BitLockerSupported) {
        $actions += "BitLocker desteğini kontrol edin (TPM, işletim sistemi versiyonu)"
        $actions += "Hardware/firmware güncellemelerini kontrol edin"
    }
    
    # TPM problemi
    if ($Analysis.TPMStatus -match "False|Not Available|Error") {
        $actions += "TPM'yi BIOS/UEFI'den etkinleştirin"
        $actions += "TPM'yi Windows'tan başlatın (tpm.msc)"
    }
    
    # Group Policy problemi
    if ($Analysis.PolicyIssues -contains "BitLocker policies not applied via Group Policy") {
        $actions += "Group Policy'yi manuel olarak yenileyin (gpupdate /force)"
        $actions += "GPO bağlantılarını kontrol edin"
        $actions += "WMI Filter'ları kontrol edin"
    }
    
    # Inheritance blocked
    if ($Analysis.BlockedInheritance) {
        $actions += "OU'da Group Policy inheritance'ı kontrol edin"
        $actions += "Block inheritance ayarını gözden geçirin"
    }
    
    # Policy processing errors
    if ($Analysis.PolicyProcessingErrors.Count -gt 0) {
        $actions += "Event Viewer'da Group Policy hatalarını kontrol edin"
        $actions += "Sistem yeniden başlatmayı deneyin"
    }
    
    # Hesap devre dışı
    if (-not $Analysis.AccountEnabled) {
        $actions += "Computer account'u Active Directory'de etkinleştirin"
    }
    
    return $actions
}

function Show-AnalysisResults {
    param($Results)
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "BITLOCKER POLICY ANALYSIS RESULTS" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    # Özet istatistikler
    $totalComputers = $Results.Count
    $onlineComputers = ($Results | Where-Object { $_.Online }).Count
    $supportedComputers = ($Results | Where-Object { $_.BitLockerSupported }).Count
    $policiesApplied = ($Results | Where-Object { $_.GPOApplicationStatus -contains "BitLocker policies found in RSoP" }).Count
    
    Write-Host "`nÖZET:" -ForegroundColor Yellow
    Write-Host "Toplam Bilgisayar: $totalComputers" -ForegroundColor White
    Write-Host "Çevrimiçi: $onlineComputers" -ForegroundColor Green
    Write-Host "BitLocker Destekli: $supportedComputers" -ForegroundColor Green
    Write-Host "Politika Uygulanmış: $policiesApplied" -ForegroundColor Green
    
    # Detaylı sonuçlar
    foreach ($result in $Results) {
        Write-Host "`n" + "-"*50 -ForegroundColor Gray
        Write-Host "Bilgisayar: $($result.ComputerName)" -ForegroundColor Yellow
        Write-Host "İşletim Sistemi: $($result.OperatingSystem)" -ForegroundColor Gray
        Write-Host "Çevrimiçi: $($result.Online)" -ForegroundColor $(if ($result.Online) { "Green" } else { "Red" })
        Write-Host "BitLocker Destekli: $($result.BitLockerSupported)" -ForegroundColor $(if ($result.BitLockerSupported) { "Green" } else { "Red" })
        Write-Host "TPM Durumu: $($result.TPMStatus)" -ForegroundColor Gray
        Write-Host "Son GP Yenileme: $($result.LastGroupPolicyRefresh)" -ForegroundColor Gray
        
        if ($result.PolicyIssues.Count -gt 0) {
            Write-Host "`nTespit Edilen Problemler:" -ForegroundColor Red
            $result.PolicyIssues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        }
        
        if ($result.RecommendedActions.Count -gt 0) {
            Write-Host "`nÖnerilen Aksiyonlar:" -ForegroundColor Cyan
            $result.RecommendedActions | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
        }
    }
}

function Export-AnalysisResults {
    param($Results, $OutputPath)
    
    $exportData = @()
    foreach ($result in $Results) {
        $exportData += [PSCustomObject]@{
            ComputerName = $result.ComputerName
            OperatingSystem = $result.OperatingSystem
            Online = $result.Online
            BitLockerSupported = $result.BitLockerSupported
            BitLockerStatus = $result.BitLockerStatus
            TPMStatus = $result.TPMStatus
            LastGroupPolicyRefresh = $result.LastGroupPolicyRefresh
            PolicyIssues = ($result.PolicyIssues -join "; ")
            RecommendedActions = ($result.RecommendedActions -join "; ")
            SecurityGroups = ($result.SecurityGroups -join "; ")
        }
    }
    
    $exportData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nDetaylı sonuçlar kaydedildi: $OutputPath" -ForegroundColor Green
}

# Yaygın BitLocker politika problemlerini listeleyen fonksiyon
function Get-CommonBitLockerPolicyIssues {
    Write-Host "BITLOCKER POLICY YAYGIN PROBLEMLER VE ÇÖZÜMLERİ" -ForegroundColor Cyan
    Write-Host "="*60 -ForegroundColor Cyan
    
    $issues = @(
        @{
            Problem = "TPM bulunamadı veya etkin değil"
            Cause = "Hardware TPM yok veya BIOS'ta kapalı"
            Solution = "BIOS/UEFI'den TPM'yi etkinleştirin, tpm.msc ile kontrol edin"
        },
        @{
            Problem = "BitLocker politikası uygulanmıyor"
            Cause = "WMI Filter, Security Group, veya OU yerleşimi"
            Solution = "gpresult /r ile RSoP kontrol edin, WMI Filter'ları kontrol edin"
        },
        @{
            Problem = "Group Policy inheritance blocked"
            Cause = "OU seviyesinde 'Block Inheritance' etkin"
            Solution = "GPMC'den Block Inheritance ayarını kontrol edin"
        },
        @{
            Problem = "Computer account disabled"
            Cause = "AD'de bilgisayar hesabı devre dışı"
            Solution = "Active Directory Users and Computers'dan hesabı etkinleştirin"
        },
        @{
            Problem = "İşletim sistemi BitLocker desteklemiyor"
            Cause = "Home edition, eski Windows versiyonu"
            Solution = "Pro/Enterprise sürümüne yükseltin"
        },
        @{
            Problem = "Network connectivity issues"
            Cause = "DC ile iletişim kuramıyor"
            Solution = "DNS, firewall, network bağlantısını kontrol edin"
        },
        @{
            Problem = "WMI Filter match etmiyor"
            Cause = "GPO'da WMI Filter computer'ı exclude ediyor"
            Solution = "WMI Filter query'sini ve computer özelliklerini kontrol edin"
        },
        @{
            Problem = "Security Group membership"
            Cause = "Gerekli security group'a üye değil"
            Solution = "Computer'ı doğru security group'a ekleyin"
        }
    )
    
    foreach ($issue in $issues) {
        Write-Host "`nProblem: $($issue.Problem)" -ForegroundColor Red
        Write-Host "Sebep: $($issue.Cause)" -ForegroundColor Yellow
        Write-Host "Çözüm: $($issue.Solution)" -ForegroundColor Green
    }
}

# Kullanım örnekleri
Write-Host "BitLocker Policy Troubleshooting Tool" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Kullanım örnekleri:"
Write-Host "1. Test-BitLockerPolicyDifferences -OUPath 'OU=Computers,DC=domain,DC=com'"
Write-Host "2. Test-BitLockerPolicyDifferences -ComputerNames @('PC001','PC002','PC003')"
Write-Host "3. Test-BitLockerPolicyDifferences -OUPath 'OU=Computers,DC=domain,DC=com' -OutputPath 'C:\Analysis.csv'"
Write-Host "4. Get-CommonBitLockerPolicyIssues"
Write-Host ""
Write-Host "Gereksinimler: Domain Admin yetkileri, RSAT araçları" -ForegroundColor Red
