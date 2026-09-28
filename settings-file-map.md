# Settings file over view

## higharchy


```
/
/settings.plist # file that holds the settings
/version.plist # holds the latest patcher version of Matteo and Albert, if the version is greater then the current build's, the app doesn't read or write to this file, as it could break it if a newer feature was introduced.
/data/ # folder for non text data
/data/assign.json # file to hold the function -> UUID map that links the function up to it's data
/data/(UUID)/someData # sample data
/tmp/ # folder for tempary data that does not get stored e.g the opencore build folder
```

The `data` folder, the `settings.plist` and the `version.txt` get zipped up into a `.settings` file

## Notes

when the user selects that they want o use the old .plist settings, just move the `settings.plist` file out, delete the `.settings` file and rename the `settings.plist` to the old universal name.

this file gets unzipped into the pyloads folder when the app is running

the `version.plist` file has the the eqivalent Matteo version of the upstream and the current upstream version. Since Matteo sometimes releases features before the upstream, extra work will need to be put in to make sure that the latest upstream doesn't accentally currupt the settings.