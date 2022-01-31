# VAL CONTRIBUTION TO HASHICORP VAULT

INTRO 

This modification is to make the pki engine use and external application for signing operation and only store the CA certificate (not the key). It is meant to be used with my GoPKI application (on my Github).


HOW TO DEPLOY/RUN IT

In the following to files:
- sdk/helper/certutil/helpers.go
- builtin/logical/pki/crl_util.go
Need to change the following line for the address of your external signer.
var externalPKIURL = "http://externalSigner:8080"

If you are using it with an external signer that is not my GoPKI app, you will probably also want to change the external signer endpoints. This is the one I am using:
externalPKIURL + "/receive" - for cert signing, used in sdk/helper/certutil/helpers.go
externalPKIURL + "/root.com/crl" - for crl signing, used in builtin/logical/pki/crl_util.go

Deploy quick and easy with docker/docker-compose using the included docker-complose yaml file:
$ docker-compose up -d

It can also be deployed manually in the same way Hashicorp Vault is normally deployed.


CODE MODIFICATION

1) Cert Signing (in sdk/helper/certutil/helpers.go)

1.1 Some imports

1.2 Some variable definitions

var caCertPath = "root-ca/root.der"
var externalPKIURL = "http://externalSigner:8080"

1.3 Modified the signing functions

2 functions (with and withing csr)
func SignCertificate (without CSR) (not tested)
func CreateCertificate (with CSR) (tested)
       

REPLACE

certBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, caCert, data.CSR.PublicKey, data.SigningBundle.PrivateKey)

BY 

jsonCertTemplate, err := json.Marshal(certTemplate)
if err != nil {
	panic(err)
}
jsonPublicKey, err := json.Marshal(result.PrivateKey.Public())
if err != nil {
	panic(err)
}
jsonToSend := "{\"Template\":" + string(jsonCertTemplate) + ",\"PublicKey\":" + string(jsonPublicKey) + "}"
fmt.Printf(jsonToSend)
toSend := strings.NewReader((jsonToSend))

// send and receive with with inner PKI
resp, err := http.Post(externalPKIURL + "/receive", "application/json", toSend)
if err != nil {
	panic(err)
}
respBytes, err := ioutil.ReadAll(resp.Body)
if err != nil {
	panic(err)
}

certBytes, err = base64.StdEncoding.DecodeString(string(respBytes))
if err != nil {
	panic(err)
}
//certBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, valCert, result.PrivateKey.Public(), valKey)
//fmt.Printf("ORIGINAL:%s\n", certBytes)
//certBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, caCert, result.PrivateKey.Public(), data.SigningBundle.PrivateKey)
// new stuff ends
      

 2) "Creation" of root CA in Vault (still in sdk/helper/certutil/helpers.go)

 Replace the full block
    } else {
        // Creating a self-signed root
        ...
    }

BY   

	} else {
			// Creating a self-signed root

			//new stuff begins
			certBytes, err = ioutil.ReadFile(caCertPath)
			if err != nil {
				panic(err)
			}
			//new stuff ends
		}

3) CRL Signing (in builtin/logical/pki/crl_util.go)

3.1 Some imports

3.2 Comment out "crypto/rand" in the list of imports since it will not be used anymore and Go doesn't start with an unused import.

3.3 Add the following variable

var externalPKIURL = "http://externalSigner:8080"

3.4 Modified the function buildCRL:

REPLACE

    signingBundle, caErr := fetchCAInfo(ctx, b, req)
	switch caErr.(type) {
	case errutil.UserError:
		return errutil.UserError{Err: fmt.Sprintf("could not fetch the CA certificate: %s", caErr)}
	case errutil.InternalError:
		return errutil.InternalError{Err: fmt.Sprintf("error fetching CA certificate: %s", caErr)}
	}

 	crlBytes, err := signingBundle.Certificate.CreateCRL(rand.Reader, signingBundle.PrivateKey, revokedCerts, time.Now(), time.Now().Add(crlLifetime))
	if err != nil {
		return errutil.InternalError{Err: fmt.Sprintf("error creating new CRL: %s", err)}
	}

 BY        

 	// new stuff begins
	// prepare what to send to the inner PKI
	jsonToSend := "{\"revokedCerts\":[ "
	for _, revCert := range revokedCerts {
		jsonRevCert, _ := json.Marshal(revCert)
		jsonToSend = jsonToSend + string(jsonRevCert) + ","
	}
	jsonToSend = jsonToSend[0:len(jsonToSend)-1] + "],\"CrlLifetime\":\"" + crlLifetime.String() + "\"}"
    fmt.Printf(jsonToSend)
	toSend := strings.NewReader((jsonToSend))

	// send and receive with with inner PKI
	resp, err := http.Post(externalPKIURL + "/val.com/crl", "application/json", toSend)
	if err != nil {
		panic(err)
	}
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	crlBytes, err := base64.StdEncoding.DecodeString(string(respBytes))
	if err != nil {
		panic(err)
	}
    // new stuff ends


-----------------------    

Usefull OpenSSL commands

read cert details
$ openssl x509 -in client.pem -text
read a crl
$ openssl crl -in root.crl -text
check a certificate against trusted root CA
$ openssl verify -verbose -CAfile root.pem client.pem
check a certificate against trusted root CA and a CRL
$ cat root.pem root.crl >> chain.pem
$ openssl verify -verbose -crl_check -CAfile chain.pem client.pem


