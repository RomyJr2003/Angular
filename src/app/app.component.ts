import { Component } from '@angular/core';

import { AccountService } from '@app/_services';
import { Account, Role } from './_models';

@Component ({ selector: 'app' templateUrl: 'app.component.html'})
export class SubNavComponent {
    Role = Role;
    account = Account;

    constructor(private accountService: AccountService) {
        this.accountService.account.subscribe(x => this.account = x);
    }

    logout() {
        this.accountService.logout();
    }
}