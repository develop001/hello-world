package com.opzoon.server.license.license;

import java.lang.String;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyStore;
import java.security.Principal;
import java.util.*;
import android.util.Base64;
import android.util.Log;

public class Verifier {
    private static final String TAG = Verifier.class.getName();
    private static final String CA_DN = "CN=Opzoon Ltd,OU=Opzoon Ltd,O=Opzoon Ltd,L=Beijing,ST=Beijing,C=CN";
    private static boolean dbg = true;

    /**
     * verify if the signature is correct
     * @param     text  the plain text.
     * @param     signature the signature of text. signature is base64 encoded.
     * @param     certificate  certificate for public key extraction. ceritficate is base64 encoded.
     */
    public static boolean verifySignature( String text, String signature, String certificate ) {
        try {
            if( dbg ) {
                Log.e( TAG, "=============================================================" );
                Log.e( TAG, text );
                Log.e( TAG, signature );
                Log.e( TAG, certificate );
                Log.e( TAG, "=============================================================" );
            }

            byte[] textByte = text.getBytes();
            byte[] signatureByte = Base64.decode( signature, Base64.DEFAULT );
            byte[] certByte = Base64.decode( certificate, Base64.DEFAULT );

            CertificateFactory f = CertificateFactory.getInstance( "X.509" );
            InputStream certIn = new ByteArrayInputStream( certByte );
            X509Certificate cert = (X509Certificate) f.generateCertificate( certIn );
            PublicKey pk = cert.getPublicKey();

            Signature sig = Signature.getInstance( "SHA256withRSA" );
            sig.initVerify( pk );
            sig.update( textByte );
            return sig.verify( signatureByte );
        } catch( Exception e) {
            if( dbg ) {
                Log.e( TAG, e.getMessage() );
                e.printStackTrace();
            }
            return false;
        }

    }

    /**
     * check if the certificate is issued by Opzoon
     * @param certificate the certificate to be verified. certificate should be in base64 coded x509 der format
     */
    public static boolean verifyCertificate( String certificate ) {
        if( dbg ) {
            Log.e( TAG, certificate );
        }

        PublicKey pubkey = null;
        X509Certificate targetCert = null;
        String aliasCA = null;

        try {
            CertificateFactory f = CertificateFactory.getInstance( "X.509" );
            byte[] targetCertByte = Base64.decode( certificate, Base64.DEFAULT );
            InputStream targetCertIn = new ByteArrayInputStream( targetCertByte );
            targetCert = (X509Certificate) f.generateCertificate( targetCertIn );

            KeyStore ks = KeyStore.getInstance( "AndroidCAStore" );
            ks.load( null, null ); //Load default system keystore
            Enumeration<String> aliases = ks.aliases();
            while ( aliases.hasMoreElements() ) {
                aliasCA = (String) aliases.nextElement();
                Certificate tempCert = ks.getCertificate( aliasCA );
                if ( tempCert instanceof X509Certificate ) {
                    X509Certificate tempX509Cert = (X509Certificate) tempCert;
                    Principal principal = tempX509Cert.getIssuerDN();
                    String issuerDn = principal.getName();
                    if( issuerDn.equals( CA_DN ) ) {
                        break;
                    }
                }
            }

            if( aliasCA != null ) {
                X509Certificate cert = (X509Certificate) ks.getCertificate( aliasCA );
                pubkey = cert.getPublicKey();
            } else {
                return false;
            }

            if( pubkey != null && targetCert != null ) {
                targetCert.verify( pubkey );
                return true;
            }
        } catch( Exception e ) {
            if(dbg) {
                Log.e(TAG, e.getMessage());
                e.printStackTrace();
            }
            return false;
        }

        return false;
    }

}
