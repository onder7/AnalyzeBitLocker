# AnalyzeBitLocker
Reasons why computers in the same OU receive different BitLocker policies
This PowerShell script analyzes why computers in the same OU receive different BitLocker policies. Here are the main categories of reasons:
<img width="658" height="425" alt="image" src="https://github.com/user-attachments/assets/957c75c3-fc00-462c-9aab-fd2225947516" />

Main Problems and Causes:
1. Hardware/System Requirements
Missing or disabled TPM (Trusted Platform Module)
BitLocker-unsupported Windows version (Home edition)
UEFI/Legacy boot mode differences
Secure Boot status
2. Group Policy Application Issues
WMI Filters - If there is a WMI filter in the GPO and the computer does not pass this filter
Security Group memberships - Being in different security groups
Block Inheritance - If inheritance is blocked at the OU level
GPO Link order and priority differences
3. Network and Connection Issues
Communication problem with the Domain Controller
DNS resolution issues
Firewall/network policy differences
Being offline
4. System Status Differences
Computer account disabled/expired
Last Group Policy refresh time
Group Policy errors in event logs
Registry corruption
5. Timing and Synchronization
Time the computer joined the domain
Time the GPO was linked to the OU
Policy replication delays
Usage Examples:

powershell
# Analyze all computers in a specific OU
Test-BitLockerPolicyDifferences -OUPath "OU=Computers,DC=domain,DC=com"

# Compare specific computers
Test-BitLockerPolicyDifferences -ComputerNames @("PC001","PC002","PC003")

# Save results to CSV
Test-BitLockerPolicyDifferences -OUPath "OU=Computers,DC=domain,DC=com" -OutputPath "C:\Analysis.csv"

# List common issues
Get-CommonBitLockerPolicyIssues

Areas Analyzed by the Script:
✅ Online/Offline status ✅ BitLocker hardware support ✅ TPM status ✅ Group Policy application status ✅ Security Group memberships ✅ WMI Filters ✅ Inheritance blocking ✅ Event log errors ✅ Registry status ✅ Last GP refresh time

The script also provides recommended actions for each computer and offers concrete steps for resolving issues.


## Aynı OU'da bulunan bilgisayarların BitLocker politikalarını farklı şekilde almasının sebeplerini analiz eden bir PowerShell scripti yazabilirim:Bu PowerShell scripti, aynı OU'da bulunan bilgisayarların BitLocker politikalarını neden farklı şekilde aldığını analiz eder. 
İşte ana sebep kategorileri:

## **Ana Problemler ve Sebepleri:**

### **1. Hardware/Sistem Gereksinimleri**
- **TPM (Trusted Platform Module) eksikliği veya devre dışı**
- **BitLocker desteklenmeyen Windows sürümü** (Home edition)
- **UEFI/Legacy boot mode farkları**
- **Secure Boot durumu**

### **2. Group Policy Uygulama Sorunları**
- **WMI Filter'lar** - GPO'da WMI filter varsa ve computer bu filter'ı geçmiyorsa
- **Security Group üyelikleri** - Farklı security group'larda olmak
- **Block Inheritance** - OU seviyesinde inheritance bloke edilmişse
- **GPO Link sırası ve öncelik** farkları

### **3. Network ve Bağlantı Sorunları**
- **Domain Controller ile iletişim problemi**
- **DNS çözümlenme sorunları**
- **Firewall/Network politika farkları**
- **Offline durumda olma**

### **4. Sistem Durumu Farkları**
- **Computer account disabled/expired**
- **Son Group Policy yenileme zamanı**
- **Event log'larda Group Policy hataları**
- **Registry corruption**

### **5. Timing ve Senkronizasyon**
- **Computer'ın domain'e join olma zamanı**
- **GPO'nun OU'ya link edilme zamanı**
- **Policy replication gecikmeleri**

## **Kullanım Örnekleri:**

```powershell
# Belirli OU'daki tüm bilgisayarları analiz et
Test-BitLockerPolicyDifferences -OUPath "OU=Computers,DC=domain,DC=com"

# Belirli bilgisayarları karşılaştır
Test-BitLockerPolicyDifferences -ComputerNames @("PC001","PC002","PC003")

# Sonuçları CSV'ye kaydet
Test-BitLockerPolicyDifferences -OUPath "OU=Computers,DC=domain,DC=com" -OutputPath "C:\Analysis.csv"

# Yaygın problemleri listele
Get-CommonBitLockerPolicyIssues
```

## **Script'in Analiz Ettiği Alanlar:**

✅ **Online/Offline durumu**
✅ **BitLocker hardware desteği**
✅ **TPM durumu**
✅ **Group Policy uygulama durumu**
✅ **Security Group üyelikleri**
✅ **WMI Filter'lar**
✅ **Inheritance blocking**
✅ **Event log hataları**
✅ **Registry durumu**
✅ **Son GP yenileme zamanı**

Script, her bilgisayar için önerilen aksiyonları da sağlar ve problemlerin çözümü için somut adımlar sunar.
