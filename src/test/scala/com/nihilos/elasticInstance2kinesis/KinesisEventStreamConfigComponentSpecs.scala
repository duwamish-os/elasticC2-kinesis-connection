package com.nihilos.elasticInstance2kinesis

import java.util
import java.util.UUID

import com.amazonaws.services.kinesis.clientlibrary.interfaces.{IRecordProcessor, IRecordProcessorCheckpointer, IRecordProcessorFactory}
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.{ShutdownReason, Worker}
import com.amazonaws.services.kinesis.model.{CreateStreamRequest, Record}

/**
  * Created by prayagupd
  * on 3/31/17.
  */

class KinesisEventStreamConfigComponentSpecs extends org.scalatest.FunSuite {

  val gregorsamsa = "f0123-GregorSamsa-1"

  test("creates kinesis stream") {

    val config = new KinesisEventStreamConfig

    val createRequest = new CreateStreamRequest().withStreamName(gregorsamsa).withShardCount(1)

    val response = config.getStreamConnection().createStream(createRequest)

    Thread.sleep(5000)

    assert(response.getSdkHttpMetadata.getHttpStatusCode == 200)
  }

  test("creates consumer config") {

    Thread.sleep(50000)

    val consumerConfig = new KinesisEventStreamConfig

    val nativeConsumer = new Worker.Builder()
      .recordProcessorFactory(new IRecordProcessorFactory {
        override def createProcessor(): IRecordProcessor =
          new IRecordProcessor {override def shutdown(checkpointer: IRecordProcessorCheckpointer, reason: ShutdownReason): Unit = {
            println("nobody cares about shutdown")
          }

          override def initialize(shardId: String): Unit = {
            println("nobody cares mate, its friday")
          }

          override def processRecords(records: util.List[Record], checkpointer: IRecordProcessorCheckpointer): Unit = {
            println("nobody cares mate, its friday")
          }
        }
      }).config(consumerConfig.getStreamConsumerConfig("a0135-some-consumer", UUID.randomUUID().toString, gregorsamsa))
      .dynamoDBClient(consumerConfig.getOffsetConnection())
      .build()

    new Thread(nativeConsumer).start()

    Thread.sleep(1000)

    assert(1 == 1)
  }
}
