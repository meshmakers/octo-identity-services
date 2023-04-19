import "bootstrap/dist/js/bootstrap.min"
import "bootstrap/dist/css/bootstrap.min.css"
import { library, dom } from "@fortawesome/fontawesome-svg-core";
import { faTriangleExclamation } from "@fortawesome/free-solid-svg-icons/faTriangleExclamation";
import { faCircleInfo } from "@fortawesome/free-solid-svg-icons/faCircleInfo";
import {MDCTextField} from '@material/textfield';

const textFields = document.querySelectorAll('.mdc-text-field');
textFields.forEach(textField => MDCTextField.attachTo(textField));


library.add(faCircleInfo);
library.add(faTriangleExclamation);
dom.watch();