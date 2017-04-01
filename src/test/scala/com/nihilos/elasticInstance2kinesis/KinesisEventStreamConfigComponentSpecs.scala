package com.nihilos.elasticInstance2kinesis

import com.amazonaws.services.kinesis.model.CreateStreamRequest

/**
  * Created by prayagupd
  * on 3/31/17.
  */

class KinesisEventStreamConfigComponentSpecs extends org.scalatest.FunSuite {

  test("creates kinesis stream") {

    val config = new KinesisEventStreamConfig

    val createRequest = new CreateStreamRequest().withStreamName("GregorSamsa").withShardCount(1)

    val response = config.getStreamConnection().createStream(createRequest)
    assert(response.getSdkHttpMetadata.getHttpStatusCode == 200)
  }

}
