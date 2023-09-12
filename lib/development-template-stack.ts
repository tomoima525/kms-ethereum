import {
  Aws,
  Duration,
  Stack,
  StackProps,
  aws_lambda as lambda,
} from "aws-cdk-lib";
import * as lambda_nodejs from "aws-cdk-lib/aws-lambda-nodejs";
import * as kms from "aws-cdk-lib/aws-kms";
import { Construct } from "constructs";
import path = require("path");
import { Effect, PolicyStatement } from "aws-cdk-lib/aws-iam";

export class DevelopmentTemplateStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const kmsPolicy = new PolicyStatement({
      effect: Effect.ALLOW,
      actions: ["kms:GetPublicKey", "kms:Sign", "kms:CreateKey"],
      resources: ["*"],
    });

    const secretManagerPolicy = new PolicyStatement({
      effect: Effect.ALLOW,
      actions: ["secretsmanager:GetSecretValue"],
      resources: [
        `arn:aws:secretsmanager:${Aws.REGION}:${Aws.ACCOUNT_ID}:secret:*`,
      ],
    });

    // lambda
    const ethLambda = new lambda_nodejs.NodejsFunction(this, "kms-eth-lambda", {
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: "handler",
      entry: path.join(
        `${__dirname}/../`,
        "functions",
        "kms-eth-lambda/index.ts",
      ),
      memorySize: 512,
      timeout: Duration.seconds(30),
    });

    ethLambda.addToRolePolicy(kmsPolicy);
    ethLambda.addToRolePolicy(secretManagerPolicy);
  }
}
