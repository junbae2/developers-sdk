package com.github.ryukato.link.developers.sdk.http

import org.apache.commons.codec.binary.Base64
import org.apache.commons.lang3.StringUtils
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

@Suppress("unused")
fun signature(
    serviceApiSecret: String,
    httpMethod: String, // GET, POST, PUT, and DELETE
    path: String,
    timestamp: Long,
    nonce: String,
    queryParam: Map<String, List<String?>> = emptyMap(),
    body: Map<String, Any?> = emptyMap()
): String {
    val bodyTreeMap = TreeMap<String, Any?>()
    bodyTreeMap.putAll(body)

    val flatQueryParam = flattenParams(queryParam)
    val flattenBody = flattenBody(bodyTreeMap)

    val stringBuilder = StringBuilder()
    stringBuilder.append("$nonce$timestamp$httpMethod$path")

    if (flatQueryParam.isNotBlank()) {
        if ("?" in flatQueryParam) {
            stringBuilder.append(flatQueryParam)
        } else {
            stringBuilder.append("?").append(flatQueryParam)
        }
    }
    if (flattenBody.isNotBlank()) {
        if (!stringBuilder.contains('?')) {
            stringBuilder.append("?").append(flattenBody)
        } else {
            stringBuilder.append("&").append(flattenBody)
        }
    }

    val hmac512 = "HmacSHA512"
    val signingKey = SecretKeySpec(serviceApiSecret.toByteArray(), hmac512)
    val mac = Mac.getInstance(hmac512)
    mac.init(signingKey)
    val rawHmac = mac.doFinal(stringBuilder.toString().toByteArray())
    return Base64.encodeBase64String(rawHmac)
}

fun flattenParams(queryParams: Map<String, List<String?>>): String {
    val orderedMap = TreeMap(queryParams)
    return if (orderedMap.isEmpty()) {
        ""
    } else {
        orderedMap.filterValues { it.isNotEmpty() }.map { (k, v) ->
            "$k=${v.joinToString(",")}"
        }.joinToString("&")
    }
}

fun flattenBody(bodyTreeMap: Map<String, Any?>): String {
    return bodyTreeMap.filterValues { it != null }.map { (k, v) ->
        when (v) {
            is String -> "$k=$v"
            is List<*> -> {
                val listTreeMap = TreeMap<String, String?>()
                v as List<Map<String, String>>
                v.forEachIndexed { index, map ->
                    map.keys.union(listTreeMap.keys).forEach { key ->
                        val value = map[key] ?: StringUtils.EMPTY
                        if (listTreeMap[key] == null) {
                            listTreeMap[key] = "${",".repeat(index)}$value"
                        } else {
                            listTreeMap[key] = "${listTreeMap[key]},$value"
                        }
                    }
                }
                listTreeMap.map { (lk, kv) ->
                    "$k.$lk=$kv"
                }.joinToString("&")
            }
            else -> throw IllegalArgumentException()
        }
    }.joinToString("&")
}
