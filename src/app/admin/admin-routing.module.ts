import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { SubNavComponent } from './subnav.component';
import { LayoutComponent } from './layout.component';
import { OverviewComponent } from './overview.component';

const accountsModule = () => import('./accounts/accounts.module').then(x => x.AccountModule);

const routes: Routes = [
    { path: '', component: SubNavComponent, outlet: 'subnav'},
    {
        path: '', component: LayoutComponent,
        children: [
            { path: '', component: OverviewComponent},
            { path: 'accounts', loadChildren: accountsModule},
        ]
            
    }
];

@NglModule({
    imports: [RouterModule.forChild(routes)],
    exports: [RouterModule]
})
export class AdminRoutingModule { }