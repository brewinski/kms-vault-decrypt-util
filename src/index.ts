'use strict'
import aws from 'aws-sdk';
import fs from 'fs';
import { PromiseResult } from 'aws-sdk/lib/request';
import { DecryptResponse } from 'aws-sdk/clients/kms';
const { Vault } = require('ansible-vault');

const checkAWSLogin = async () => {
    const stsClient = new aws.STS();
    try {
        return await stsClient
            .getCallerIdentity()
            .promise();
    } catch (err) {
        console.log('Unable to verify user is logged in. Please login to AWS and export a defualt profile.');
        throw err;
    }
};

const getKMSKey = async (cipherPath: string): Promise<PromiseResult<aws.KMS.DecryptResponse, aws.AWSError>> => {
    const kmsClient = new aws.KMS({
        region: 'ap-southeast-2'
    });
    // read the cipher file.
    const CiphertextBlob = fs.readFileSync(cipherPath);
    return kmsClient.decrypt({CiphertextBlob}).promise();
};

const getVaultParameters = async (key: DecryptResponse, vaultFile: string): Promise<any> => {
    const encryptedFileContents = fs.readFileSync(vaultFile).toString();

    return new Vault({ password: key.Plaintext })
        .decrypt(encryptedFileContents);
};


const main = async ([cipherPath, vaultFile]: [string, string]) => {
    try {
        // Check AWS login result
        console.log('Checking AWS login status');
        await checkAWSLogin();
        // Get the vault password from AWS
        console.log('Getting KMS key');
        const key = await getKMSKey(cipherPath);
        // Decrypt the parameters file using the password.
        console.log('Decrypting vault file');
        const decryptedFile = await getVaultParameters(key, vaultFile);
        console.log(decryptedFile);
    } catch (err) {
        console.error(err);
    }
}

main([...process.argv.slice(2)] as [string, string]);
