import { Observable } from '@nativescript/core';

export class LoginViewModel extends Observable {
    constructor() {
        super();
    }

    onLogin() {
        // TODO: Implement secure login
        console.log('Login attempted');
    }
}