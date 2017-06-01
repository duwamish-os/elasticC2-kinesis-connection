package com.nihilos.elasticInstance2kinesis

import java.io.{ByteArrayInputStream, IOException, InputStream}
import java.security.MessageDigest
import java.util.{Base64, Properties}

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain
import com.amazonaws.services.s3.model.{ObjectMetadata, PutObjectRequest, StorageClass}
import com.amazonaws.services.s3.{AmazonS3, AmazonS3Client}

import java.io.File

/**
  * Created by prayagupd
  * on 5/31/17.
  */

class PublishToSimpleStorageService(bucket: String, contentName: String) {

  val config = new Properties() {{
    try {
      load(this.getClass.getClassLoader.getResourceAsStream("application.properties"))
    } catch {
      case x: IOException => Console.err.println(x)
    }
  }}

  def publish(content: String): (String, String) = {

    val client: AmazonS3 = new AmazonS3Client(getAuthProfileCredentials)

    val contentBytes = content.getBytes
    val inputStream: InputStream = new ByteArrayInputStream(contentBytes)

    val metadata = new ObjectMetadata
    metadata.setContentLength(contentBytes.length)

    val md5 = new String(Base64.getEncoder.encode(MessageDigest.getInstance("MD5").digest(content.getBytes())))
    println("md5 in request " + md5)
    metadata.setContentMD5(new String(Base64.getEncoder.encode(MessageDigest.getInstance("MD5").digest(content.getBytes()))))

    val putRequest = new PutObjectRequest(bucket, contentName, inputStream, metadata)
      .withMetadata(metadata)
      .withStorageClass(StorageClass.valueOf("ReducedRedundancy"))

    val putObjectResult = client.putObject(putRequest)

    println(s"ETag class: ${putObjectResult.getMetadata.getETag}; ContentHash: ${putObjectResult.getMetadata.getContentMD5}")

    (putObjectResult.getMetadata.getETag, putObjectResult.getMetadata.getContentMD5)
  }

  def publish(content: File): (String, String) = {

    val client: AmazonS3 = new AmazonS3Client(getAuthProfileCredentials)

    val putRequest = new PutObjectRequest(bucket, contentName, content)
      .withStorageClass(StorageClass.valueOf("ReducedRedundancy"))

    val putObjectResult = client.putObject(putRequest)

    println(s"Storage class: ${putObjectResult.getMetadata.getETag}; ContentHash: ${putObjectResult.getMetadata.getContentMD5}")

    (putObjectResult.getMetadata.getETag, putObjectResult.getMetadata.getContentMD5)
  }

  private def getAuthProfileCredentials: DefaultAWSCredentialsProviderChain = {
    Option(config.getProperty("authentication.profile")).map(profile =>
      System.setProperty("aws.profile", config.getProperty("authentication.profile")))

    new DefaultAWSCredentialsProviderChain
  }
}
