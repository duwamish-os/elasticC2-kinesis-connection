package com.nihilos.elasticInstance2kinesis

import java.io.{File, FileInputStream}
import java.security.MessageDigest

import org.apache.commons.codec.digest.DigestUtils
import org.scalatest.{FunSuite, Matchers}

/**
  * Created by prayagupd
  * on 5/31/17.
  */

class PublishToSimpleStorageServiceSpecs extends FunSuite with Matchers {

  test("upload to simple storage service and return content length") {

    val content = "Send me to storage-service"

    val uploadedContent = new PublishToSimpleStorageService("samsa-repo", "samsa-bytes").publish(content)

    uploadedContent._1 shouldBe DigestUtils.md5Hex(content.getBytes())

    uploadedContent._2 shouldBe null
  }

  test("sends a file") {

    val uploadedContent = new PublishToSimpleStorageService("samsa-repo", "sendme.log")
      .publish(new File("src/test/resources/sendme.log"))

    DigestUtils.md5Hex(new FileInputStream("src/test/resources/sendme.log"))

    uploadedContent._1 shouldBe DigestUtils.md5Hex(new FileInputStream("src/test/resources/sendme.log"))
    uploadedContent._2 shouldBe null
  }
}
