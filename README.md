# kms-ethereum

Sending/Signing transaction with a signer(aka Externally Owned Account) generated from a KMS key.

# Acknowledgement

This project is heavily inspired from the following projects:

- https://github.com/rjchow/ethers-aws-kms-signer
- https://github.com/odanado/cloud-cryptographic-wallet

The main difference is that this project uses the AWS SDK v3 and the latest version of the ethers library.

# Usage

```
pnpm install
```

```
pnpm cdk synth
pnpm cdk deploy --profile={your profile}
```

You can trigger lambda with the following event:

- Create Signer

```
{
  "operation": "create",
  "keyId": "3d3a13ce-df90-46f9-b8a3-e77a7e7fd687"
}
```

- Sign tx

```
{
  "operation": "sign",
  "keyId": "3d3a13ce-df90-46f9-b8a3-e77a7e7fd687",
  "to": "0x123..."
}
```

- Send tx

```
{
  "operation": "send",
  "keyId": "3d3a13ce-df90-46f9-b8a3-e77a7e7fd687",
  "to": "0x123..."
}
```

You can find my generated account here on Goerli:
https://goerli.etherscan.io/address/0xc48f32a764804c3309cb365d5822a156c318bf63

# Run Locally

If you want to run locally, then

Setup your sam local environment: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html

Setup docker: https://docs.docker.com/get-docker/

After runniing `pnpm cdk synth`, run below

```

sam local invoke -t ./cdk.out/KMSEthereum.template.json kms-eth-lambda -e ./test/send-event.json --profile={your profile}

```

```

```
