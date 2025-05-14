import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
// passport의 jwt 전략을 수행하겠다 ??? 
export class JwtAuthGuard extends AuthGuard('jwt') { }
