name := "elastic2-to-kinesis"

version := "1.0"

scalaVersion := "2.11.8"

libraryDependencies += "com.amazonaws" % "aws-java-sdk" % "1.11.109"

libraryDependencies += "com.amazonaws" % "amazon-kinesis-client" % "1.7.5"

libraryDependencies += "org.scalatest" % "scalatest_2.11" % "3.0.1"

libraryDependencies += "log4j" % "log4j" % "1.2.17"

libraryDependencies += "net.logstash.log4j" % "jsonevent-layout" % "1.7"
