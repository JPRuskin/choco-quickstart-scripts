function New-TestVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter()]
        [string]$Name = "qsg-$((New-Guid).ToString() -replace '-' -replace '^(.{11}).+$', '$1')",

        [ValidateSet("Win2022AzureEditionCore", "Win2019Datacenter")]
        [string]$Image = "Win2022AzureEditionCore",

        [ArgumentCompleter({
            param($a,$b,$WordToComplete,$d,$e)
            if (-not $script:VmSizes) {
                $script:VmSizes = Get-AzVMSize -Location 'eastus2'
            }
            $script:VmSizes.Name.Where{$_ -like "*$WordToComplete*"}
        })]
        [string]$Size = 'Standard_B4ms'
    )

    if (-not (Get-AzVM -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue)) {
        $VmArgs = @{
            ResourceGroup = $ResourceGroupName
            Name = $Name
            PublicIpAddressName = "$Name-ip"
            DomainNameLabel = $Name
            PublicIpSku = 'Basic'
            Image = $Image
            Size = $Size
            SecurityGroupName = "$ResourceGroupName-nsg"
            VirtualNetworkName = "$Name-vnet"
            NetworkInterfaceDeleteOption = 'Delete'
            OSDiskDeleteOption = 'Delete'
            Credential = [PSCredential]::new(
                'ccmadmin',
                (ConvertTo-SecureString "$(New-Guid)" -AsPlainText -Force)
            )
        }

        Write-Host "Creating VM '$($VmArgs.Name)'"
        $VM = New-AzVM @VmArgs
        $VM | Add-Member -MemberType NoteProperty -Name Credential -Value $VmArgs.Credential -PassThru
    }
}

function Request-WinRmAccessForTesting {
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter()]
        [string]$VmName,

        [Parameter()]
        [string]$IpAddress = $(Invoke-RestMethod https://api.ipify.org)
    )
    if ($NetworkSecurityGroup = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $ResourceGroupName-nsg -ErrorAction SilentlyContinue) {
        $RuleArgs = @{
            NetworkSecurityGroup = $NetworkSecurityGroup
            Name = "AllowWinRMSecure$($IpAddress -replace '\.')"
            Description = "Allow WinRM over HTTPS for '$($IpAddress)'"
            Access = "Allow"
            Protocol = "Tcp"
            Direction = "Inbound"
            Priority = 300
            SourceAddressPrefix = $IpAddress
            SourcePortRange = "*"
            DestinationAddressPrefix = "*"
            DestinationPortRange = 5986
        }

        if (($Rules = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NetworkSecurityGroup).Name -notcontains $RuleArgs.Name) {
            Write-Host "Adding WinRM Rule to '$($NetworkSecurityGroup.Name)'"
            while ($Rules.Priority -contains $RuleArgs.Priority) {
                $RuleArgs.Priority++
            }
            $NewRules = Add-AzNetworkSecurityRuleConfig @RuleArgs
        }

        if ($NewRules) {
            $null = Set-AzNetworkSecurityGroup -NetworkSecurityGroup $NetworkSecurityGroup
        }
    }

    if ($VmName) {
        Write-Host "Enabling Remote PowerShell on '$($VMName)'"
        $null = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId EnableRemotePS
    }
}