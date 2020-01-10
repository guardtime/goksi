# KSI Go SDK #
Guardtime KSI Blockchain is an industrial scale blockchain platform that cryptographically
ensures data integrity and proves time of existence. Its signatures, based on hash chains, link data to global
calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term
integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical
example is signing of any type of logs - system logs, financial transactions, call records, etc. For more,
see [https://guardtime.com](https://guardtime.com).

The `KSI Go SDK` is a software development kit for developers who want to integrate KSI with their Go based applications
and systems. It provides an API for all KSI functionality, including the core functions - signing of data, extending
and verifying the signatures.

## Installation ##

For building and installing just use the standard go tools.

In order to run system tests successfully you need to have access to KSI service and must create KSI configuration file.
To get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).
Create KSI configuration to the file `test/systest.conf.json`, see file `test/systest.conf.json.sample` for more information.

## Proxy Configuration ##

To use a proxy, you need to configure the proxy on your operating system.

Set the system environment variable: `http_proxy=user:pass@server:port`

In the Windows control panel:

1) Find the 'System' page and select 'Advanced system settings'
2) Select 'Environment Variables...'
3) Select 'New...' to create a new system variable
4) Enter `http_proxy` in the name field and and proxy configuration (see above) in the value field.

In Linux add the system variable to `/etc/bashrc`:
~~~
	export http_proxy=user:pass@server:port
~~~

Configuring authentication is not supported by the Windows control panel and registry.


## Usage ##

In order to get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).

A simple example on how to sign a document:
```go
    // Open file ti be signed.
    docFile, err := os.Open("file.txt")
    if err != nil {
        return err
    }
    defer docFile.Close()
    
    // Create document hash.
    hsr, err := hash.Default.New()
    if err != nil {
        return err
    }
    if _, err := io.Copy(hsr, docFile); err != nil {
        return err
    }
    docHash, err := hsr.Imprint()
    if err != nil {
        return err
    }
    
    // Initialize signing service and sign the document hash.
    signer, err := service.NewSigner(service.OptEndpoint("http://signingservice.somehost:1234", "user", "key"))
    if err != nil {
        return err
    }
    ksiSignature, err := signer.Sign(docHash)
    if err != nil {
        return err
    }
```

And another example on how to validate the signature created above using a publication file:
```go
	pfHandler, err := publications.NewFileHandler(
		publications.FileHandlerSetPublicationsURL("http://verify.guardtime.com/ksi-publications.bin"),
		publications.FileHandlerSetFileCertConstraint(publications.OidEmail, "publications@guardtime.com"),
	)
	if err != nil {
		return err
	}
	extender, err := service.NewExtender(pfHandler,
		service.OptEndpoint("http://extendingservice.somehost:1234", "user", "key"),
	)
	if err != nil {
		return err
	}
	if err := ksiSignature.Verify(signature.DefaultVerificationPolicy,
		signature.VerCtxOptExtendingPermitted(true),
		signature.VerCtxOptCalendarProvider(extender),
		signature.VerCtxOptPublicationsFileHandler(pfHandler),
	); err != nil {
		return err
	}
```

The API full reference is available on [GoDoc](http://godoc.org/github.com/guardtime/goksi).


## Dependencies ##

The project depends on [fullsailor/pkcs7](https://github.com/fullsailor/pkcs7).

## Compatibility ##

Go 1.10 or newer.

## Contributing ##

See `CONTRIBUTING.md` file.

## License ##

See `LICENSE` file.
