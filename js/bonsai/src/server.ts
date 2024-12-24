import dotenv from 'dotenv';
dotenv.config();

export enum SessionType {
    ImageId,
    Prove,
    Snark
}

interface ConstructorOptions {
    bonsaiApiKey: string;
    bonsaiUrl?: string;
    risc0Version?: string;
}

const bonsaiRequestHeaders = (apiKey: string, risc0Version: string) => {
    return {
        'x-api-key': apiKey,
        'x-risc0-version': risc0Version,
        'accept': 'application/json'
    }
}

export default class Server {
    bonsaiApiKey: string;

    bonsaiUrl: string;

    risc0Version: string;

    // do not suffix URL with slash
    constructor(options: ConstructorOptions) {
        this.bonsaiApiKey = options.bonsaiApiKey;
        this.bonsaiUrl = options.bonsaiUrl ? options.bonsaiUrl : "https://api.bonsai.xyz";
        this.risc0Version = options.risc0Version ? options.risc0Version : "1.0.1";
    }

    async checkStatus(session: SessionType, uuid: string): Promise<Response> {
        let url: string;

        switch (session) {
            case SessionType.ImageId:
                url = this.bonsaiUrl + `/images/upload/${uuid}`;
                break;
            case SessionType.Prove:
                url = this.bonsaiUrl + `/sessions/status/${uuid}`;
                break;
            case SessionType.Snark:
                url = this.bonsaiUrl + `/snark/status/${uuid}`;
        }

        const reqOptions = {
            method: 'GET',
            headers: bonsaiRequestHeaders(this.bonsaiApiKey, this.risc0Version),
        }

        const response = await fetch(url, reqOptions);
        return response;
    }

    async createProofSession(
        imageId: string,
        inputId: string = "",
        input: string = "",
        assumptions?: Array<string>
    ): Promise<string> {
        if (input.length === 0 && inputId.length === 0) {
            throw new Error("Must provide either an input or inputId");
        }

        if (inputId.length == 0) {
            // upload the input here...
            let inputBuffer = Buffer.from(input, 'hex');
            const requestUrl = this.bonsaiUrl + `/inputs/upload`;
            const requestOptions = {
                method: 'GET',
                headers: bonsaiRequestHeaders(this.bonsaiApiKey, this.risc0Version)
            };
            const requestResponse = await fetch(requestUrl, requestOptions);
            if (requestResponse.status != 200) {
                throw new Error("Failed to get inputId...");
            }
            const requestResponseBody = await requestResponse.json();
            const uploadUrl = requestResponseBody.url;
            inputId = requestResponseBody.uuid;

            const uploadReqOptions = {
                method: "PUT",
                body: inputBuffer
            };
            const uploadResponse = await fetch(uploadUrl, uploadReqOptions);
            if (uploadResponse.status !== 200) {
                throw new Error("Failed to upload input...");
            }
        }

        const url = this.bonsaiUrl + `/sessions/create`;
        const reqBody = {
            img: imageId,
            input: inputId,
            assumptions: assumptions ? assumptions : new Array(0)
        };

        const reqOption = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...bonsaiRequestHeaders(this.bonsaiApiKey, this.risc0Version)
            },
            body: JSON.stringify(reqBody)
        };
        const response = await fetch(url, reqOption);
        const responseBody = (await response.json());

        return responseBody.uuid;
    }

    async createSnarkSession(proveUuid: string): Promise<string> {
        const url = this.bonsaiUrl + `/snark/create`;
        const reqOption = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...bonsaiRequestHeaders(this.bonsaiApiKey, this.risc0Version)
            },
            body: JSON.stringify({
                'session_id': proveUuid
            })
        };
        const responseStr = await fetch(url, reqOption);
        const response = (await responseStr.json());
        return response.uuid;
    }
}