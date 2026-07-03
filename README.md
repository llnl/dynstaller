# dynstaller

## Installing Windows Sandbox

Instructions are provided by Microsoft [here](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install). Otherwise, open a PowerShell terminal as an administrator and run the following command:
```powershell
Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
```

## Running Windows Sandbox

To run a .wsb (Windows Sandbox configuration file), you can double-click the file in File Explorer or pass it via command line:
```
"C:\Windows\System32\WindowsSandbox.exe" "C:\path\to\your\file.wsb"
```

## Support

Full user guides for dynstaller are available [online](https://dynstaller.readthedocs.io)
and in the [docs](./docs) directory.

For questions or support, please create a new discussion on [GitHub Discussions](https://github.com/LLNL/dynstaller/discussions/categories/q-a), 
or [open an issue](https://github.com/LLNL/dynstaller/issues/new/choose) for bug reports and feature requests.

## Contributing

Contributions are welcome. Bug fixes or minor changes are preferred via a
pull request to the [dynstaller GitHub repository](https://github.com/LLNL/dynstaller).
For more information on contributing see the [CONTRIBUTING](./CONTRIBUTING.md) file.

## License

dynstaller is released under the MIT license. See the [LICENSE](./LICENSE)
and [NOTICE](./NOTICE) files for details. All new contributions must be made
under this license.

SPDX-License-Identifier: MIT

LLNL-CODE-2015017
