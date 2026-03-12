#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib/core';
import { AwsMcpLambdaStack } from '../lib/aws-mcp-lambda-stack';

const app = new cdk.App();
new AwsMcpLambdaStack(app, process.env.STACK_NAME!, {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});
