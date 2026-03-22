package com.juanma0511.rootdetector.detector

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.juanma0511.rootdetector.model.CheckStatus
import com.juanma0511.rootdetector.model.HwCheckItem
import com.juanma0511.rootdetector.model.HwGroup
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

class KeyAttestationChecker(private val context: Context) {

    private val GOOGLE_ROOT_CA_CN = "CN=Android Keystore Root CA"
    private val GOOGLE_ROOT_CA_CN_2 = "CN=Google Hardware Attestation Root CA"
    private val GOOGLE_ROOT_CA_CN_3 = "CN=Google Cloud Attestation Root CA"

    fun runAllChecks(): List<HwCheckItem> {
        val items = mutableListOf<HwCheckItem>()
        items += checkKeyAttestationChain(strongBox = false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            items += checkKeyAttestationChain(strongBox = true)
        }
        items += checkRootCertTrust()
        return items
    }

    fun checkKeyAttestationChain(strongBox: Boolean): HwCheckItem {
        val label = if (strongBox) "StrongBox" else "TEE"
        val id = if (strongBox) "attest_chain_sb" else "attest_chain_tee"

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return det(id, "Key Attestation ($label)",
                HwGroup.KEYSTORE, CheckStatus.UNKNOWN,
                "Key attestation requires Android 7.0+", "Android < 7.0")
        }

        return try {
            val alias = "rootdetector_attest_${if (strongBox) "sb" else "tee"}"
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            ks.deleteEntry(alias)

            val challenge = "RootDetectorChallenge".toByteArray()

            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)

            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                specBuilder.setIsStrongBoxBacked(true)
            }

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(specBuilder.build())
            kpg.generateKeyPair()

            val chain = ks.getCertificateChain(alias)
            ks.deleteEntry(alias)

            if (chain == null || chain.isEmpty()) {
                return det(id, "Key Attestation ($label)",
                    HwGroup.KEYSTORE, CheckStatus.FAIL,
                    "No certificate chain returned from keystore",
                    "getCertificateChain() returned null/empty")
            }

            val certs = chain.map { it as X509Certificate }
            val chainResult = verifyChain(certs)
            val rootResult = identifyRoot(certs.last())

            val status = when {
                chainResult != null -> CheckStatus.FAIL
                rootResult.isGoogleRoot -> CheckStatus.PASS
                else -> CheckStatus.WARN
            }

            val detail = buildString {
                append("Chain depth: ${certs.size}\n")
                append("Security level: $label\n")
                append("Root: ${certs.last().subjectX500Principal.name.take(60)}\n")
                if (rootResult.isGoogleRoot) append("Root: Google Hardware Attestation CA\n")
                else append("Root: NOT Google — custom or leaked key\n")
                if (chainResult != null) append("Chain error: $chainResult\n")
            }.trim()

            det(id, "Key Attestation ($label)",
                HwGroup.KEYSTORE, status,
                "Generates an attested key and verifies the certificate chain. Google root = genuine hardware.",
                detail)

        } catch (e: StrongBoxUnavailableException) {
            det(id, "Key Attestation (StrongBox)",
                HwGroup.KEYSTORE, CheckStatus.UNKNOWN,
                "StrongBox not available on this device",
                "No dedicated security chip (normal on most devices)")
        } catch (e: Exception) {
            det(id, "Key Attestation ($label)",
                HwGroup.KEYSTORE, CheckStatus.UNKNOWN,
                "Key attestation check failed",
                e.message?.take(120))
        }
    }

    fun checkRootCertTrust(): HwCheckItem {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return det("attest_root_trust", "Attestation Root Trust",
                HwGroup.KEYSTORE, CheckStatus.UNKNOWN,
                "Requires Android 7.0+", null)
        }
        return try {
            val alias = "rootdetector_trust_check"
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            ks.deleteEntry(alias)

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge("trust_check".toByteArray())
                    .build()
            )
            kpg.generateKeyPair()

            val chain = ks.getCertificateChain(alias)
            ks.deleteEntry(alias)

            if (chain == null || chain.isEmpty()) {
                return det("attest_root_trust", "Attestation Root Trust",
                    HwGroup.KEYSTORE, CheckStatus.FAIL,
                    "No certificate chain", null)
            }

            val root = chain.last() as X509Certificate
            val rootInfo = identifyRoot(root)
            val chainError = verifyChain(chain.map { it as X509Certificate })

            val status = when {
                chainError != null -> CheckStatus.FAIL
                rootInfo.isGoogleRoot -> CheckStatus.PASS
                rootInfo.isSamsungRoot -> CheckStatus.PASS
                else -> CheckStatus.WARN
            }

            val detail = buildString {
                append("Root CN: ${root.subjectX500Principal.name.take(80)}\n")
                append("Issuer: ${root.issuerX500Principal.name.take(80)}\n")
                when {
                    rootInfo.isGoogleRoot -> append("Trusted: Google Hardware Attestation Root")
                    rootInfo.isSamsungRoot -> append("Trusted: Samsung Knox Attestation Root")
                    else -> append("WARNING: Unknown root — may be spoofed (TrickyStore/TEESimulator)")
                }
                if (chainError != null) append("\nChain error: $chainError")
            }.trim()

            det("attest_root_trust", "Attestation Root Trust",
                HwGroup.KEYSTORE, status,
                "Verifies that the attestation chain is rooted in a trusted Google or Samsung CA",
                detail)

        } catch (e: Exception) {
            det("attest_root_trust", "Attestation Root Trust",
                HwGroup.KEYSTORE, CheckStatus.UNKNOWN,
                "Could not verify root trust", e.message?.take(80))
        }
    }

    private fun verifyChain(certs: List<X509Certificate>): String? {
        try {
            for (i in 0 until certs.size - 1) {
                val cert = certs[i]
                val issuer = certs[i + 1]
                try {
                    cert.verify(issuer.publicKey)
                } catch (e: Exception) {
                    return "Cert[$i] not signed by cert[${i+1}]: ${e.message?.take(60)}"
                }
                try {
                    cert.checkValidity()
                } catch (e: Exception) {
                    return "Cert[$i] validity check failed: ${e.message?.take(60)}"
                }
            }
            val root = certs.last()
            try {
                root.verify(root.publicKey)
            } catch (e: Exception) {
                return "Root not self-signed: ${e.message?.take(60)}"
            }
            return null
        } catch (e: Exception) {
            return "Chain verification error: ${e.message?.take(80)}"
        }
    }

    private data class RootInfo(val isGoogleRoot: Boolean, val isSamsungRoot: Boolean)

    private fun identifyRoot(root: X509Certificate): RootInfo {
        val subjectDN = root.subjectX500Principal.name.lowercase()
        val issuerDN = root.issuerX500Principal.name.lowercase()

        val isGoogle = subjectDN.contains("google") ||
                subjectDN.contains("android keystore root") ||
                subjectDN.contains("android attestation root") ||
                issuerDN.contains("google")

        val isSamsung = subjectDN.contains("samsung") ||
                subjectDN.contains("knox") ||
                issuerDN.contains("samsung")

        return RootInfo(isGoogle, isSamsung)
    }

    private fun det(
        id: String, name: String, group: HwGroup,
        status: CheckStatus, description: String, detail: String?
    ) = HwCheckItem(
        id = id, name = name, description = description,
        group = group, status = status,
        value = when (status) {
            CheckStatus.PASS -> "Verified"
            CheckStatus.FAIL -> "Failed"
            CheckStatus.WARN -> "Warning"
            CheckStatus.UNKNOWN -> "N/A"
        },
        detail = detail
    )
}
