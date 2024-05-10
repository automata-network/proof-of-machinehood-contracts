import dotenv from 'dotenv';
dotenv.config();

const { BONSAI_URL } = process.env;

export enum SessionType {
    ImageId,
    Prove,
    Snark
}

interface UUIDResponse {
    uuid: string
}

export async function checkStatus(session: SessionType, uuid: string): Promise<any> {
    let sessionName: string = '';

    switch (session) {
        case SessionType.ImageId:
            sessionName = 'iamge';
            break;
        case SessionType.Prove:
            sessionName = 'prove';
            break;
        case SessionType.Snark:
            sessionName = 'snark';
    }
    
    const url = BONSAI_URL! + `/check/${sessionName}?uuid=${uuid}`;
    const responseStr = await fetch(url);
    const response = await responseStr.json();
    return response;
}

export async function createProofSession(
    imageId: string,
    inputId: string = "",
    input: string = "",
    assumptions?: Array<string>
): Promise<string> {
    if (input.length === 0 && inputId.length === 0) {
        throw new Error("Must provide either an input or inputId");
    }
    const url = BONSAI_URL! + `/prove`;
    const reqBody = {
        imageId: imageId,
        input: input,
        inputId: inputId,
        assumptions: assumptions
    };
    const reqOption = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(reqBody)
    };
    const responseStr = await fetch(url, reqOption);
    const response = (await responseStr.json()) as UUIDResponse;
    return response.uuid;
}

export async function createSnarkSession(proveUuid: string): Promise<string> {
    const url = BONSAI_URL + `/snark/session?uuid=${proveUuid}`;
    const reqOption = {
        method: 'POST'
    };
    const responseStr = await fetch(url, reqOption);
    const response = (await responseStr.json()) as UUIDResponse;
    return response.uuid;
}