import { AccountService } from '@app/_services';

export function appInitializer(accountService: AcccountService) {
    return () => new Promise(resolve => {
        //attempt to refresh token on app start up to auto authenticate
        accountService.refreshToken()
            .subscribe()
            .add(resolve);
    })
}