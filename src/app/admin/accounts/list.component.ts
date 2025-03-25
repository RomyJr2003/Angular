import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';

import { AccountService } from '@app/_services';
import { Account } from '@app/_models';

@Component({ templateUrl: 'list.component.html'})
export class ListComponent implements OnInit {
    accounts: any[];

    constructor(private accountService: AccountService) {}
        
        ngOnIt() {
            this.accountService.getAll()
            .pipe(first())
            .subscribe(account => this.accounts = accounts);
        }

        deleteAccount(id: string) {
            const account = this.accounts.find(x => x.id === id);
        }
}